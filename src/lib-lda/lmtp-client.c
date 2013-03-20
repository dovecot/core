/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dns-lookup.h"
#include "lmtp-client.h"

#include <ctype.h>

#define LMTP_MAX_LINE_LEN 1024
#define LMTP_CLIENT_DNS_LOOKUP_TIMEOUT_MSECS (60*1000)

enum lmtp_input_state {
	LMTP_INPUT_STATE_GREET,
	LMTP_INPUT_STATE_LHLO,
	LMTP_INPUT_STATE_MAIL_FROM,
	LMTP_INPUT_STATE_RCPT_TO,
	LMTP_INPUT_STATE_DATA_CONTINUE,
	LMTP_INPUT_STATE_DATA,
	LMTP_INPUT_STATE_XCLIENT
};

struct lmtp_rcpt {
	const char *address;
	lmtp_callback_t *rcpt_to_callback;
	lmtp_callback_t *data_callback;
	void *context;

	unsigned int data_called:1;
	unsigned int failed:1;
};

struct lmtp_client {
	pool_t pool;
	int refcount;

	struct lmtp_client_settings set;
	const char *host;
	struct ip_addr ip;
	unsigned int port;
	enum lmtp_client_protocol protocol;
	enum lmtp_input_state input_state;
	const char *global_fail_string;
	string_t *input_multiline;
	const char **xclient_args;

	struct dns_lookup *dns_lookup;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	int fd;

	void (*data_output_callback)(void *);
	void *data_output_context;

	lmtp_finish_callback_t *finish_callback;
	void *finish_context;

	const char *data_header;
	ARRAY(struct lmtp_rcpt) recipients;
	unsigned int rcpt_next_receive_idx;
	unsigned int rcpt_next_data_idx;
	unsigned int rcpt_next_send_idx;
	struct istream *data_input;
	unsigned char output_last;

	unsigned int xclient_sent:1;
	unsigned int rcpt_to_successes:1;
	unsigned int output_finished:1;
	unsigned int finish_called:1;
};

static void lmtp_client_send_rcpts(struct lmtp_client *client);

struct lmtp_client *
lmtp_client_init(const struct lmtp_client_settings *set,
		 lmtp_finish_callback_t *finish_callback, void *context)
{
	struct lmtp_client *client;
	pool_t pool;

	i_assert(*set->mail_from == '<');
	i_assert(*set->my_hostname != '\0');

	pool = pool_alloconly_create("lmtp client", 512);
	client = p_new(pool, struct lmtp_client, 1);
	client->refcount = 1;
	client->pool = pool;
	client->set.mail_from = p_strdup(pool, set->mail_from);
	client->set.my_hostname = p_strdup(pool, set->my_hostname);
	client->set.dns_client_socket_path =
		p_strdup(pool, set->dns_client_socket_path);
	client->set.source_ip = set->source_ip;
	client->set.source_port = set->source_port;
	client->set.proxy_ttl = set->proxy_ttl;
	client->set.proxy_timeout_secs = set->proxy_timeout_secs;
	client->finish_callback = finish_callback;
	client->finish_context = context;
	client->fd = -1;
	client->input_multiline = str_new(default_pool, 128);
	p_array_init(&client->recipients, pool, 16);
	return client;
}

void lmtp_client_close(struct lmtp_client *client)
{
	if (client->dns_lookup != NULL)
		dns_lookup_abort(&client->dns_lookup);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->input != NULL)
		i_stream_close(client->input);
	if (client->output != NULL)
		o_stream_close(client->output);
	if (client->fd != -1) {
		net_disconnect(client->fd);
		client->fd = -1;
	}
	if (client->data_input != NULL)
		i_stream_unref(&client->data_input);
	client->output_finished = TRUE;

	if (!client->finish_called) {
		client->finish_called = TRUE;
		client->finish_callback(client->finish_context);
	}
}

static void lmtp_client_ref(struct lmtp_client *client)
{
	client->refcount++;
}

static void lmtp_client_unref(struct lmtp_client **_client)
{
	struct lmtp_client *client = *_client;

	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return;

	i_assert(client->finish_called);
	if (client->input != NULL)
		i_stream_unref(&client->input);
	if (client->output != NULL)
		o_stream_unref(&client->output);
	str_free(&client->input_multiline);
	pool_unref(&client->pool);
}

void lmtp_client_deinit(struct lmtp_client **_client)
{
	struct lmtp_client *client = *_client;

	*_client = NULL;

	lmtp_client_close(client);
	lmtp_client_unref(&client);
}

const char *lmtp_client_state_to_string(struct lmtp_client *client)
{
	uoff_t size;

	switch (client->input_state) {
	case LMTP_INPUT_STATE_GREET:
		return "greeting";
	case LMTP_INPUT_STATE_LHLO:
		return "LHLO";
	case LMTP_INPUT_STATE_MAIL_FROM:
		return "MAIL FROM";
	case LMTP_INPUT_STATE_RCPT_TO:
		return "RCPT TO";
	case LMTP_INPUT_STATE_DATA_CONTINUE:
		return "DATA init";
	case LMTP_INPUT_STATE_DATA:
		if (client->output_finished)
			return "DATA reply";
		else if (i_stream_get_size(client->data_input, FALSE, &size) > 0) {
			return t_strdup_printf(
				"DATA (%"PRIuUOFF_T"/%"PRIuUOFF_T")",
				client->data_input->v_offset, size);
		} else {
			return t_strdup_printf("DATA (%"PRIuUOFF_T"/?)",
					       client->data_input->v_offset);
		}
	case LMTP_INPUT_STATE_XCLIENT:
		return "XCLIENT";
	}
	return "??";
}

void lmtp_client_fail(struct lmtp_client *client, const char *line)
{
	struct lmtp_rcpt *recipients;
	unsigned int i, count;

	client->global_fail_string = p_strdup(client->pool, line);

	lmtp_client_ref(client);
	recipients = array_get_modifiable(&client->recipients, &count);
	for (i = client->rcpt_next_receive_idx; i < count; i++) {
		recipients[i].rcpt_to_callback(FALSE, line,
					       recipients[i].context);
		recipients[i].failed = TRUE;
	}
	client->rcpt_next_receive_idx = count;

	for (i = client->rcpt_next_data_idx; i < count; i++) {
		if (!recipients[i].failed) {
			recipients[i].data_callback(FALSE, line,
						    recipients[i].context);
		}
	}
	client->rcpt_next_data_idx = count;

	lmtp_client_close(client);
	lmtp_client_unref(&client);
}

static void
lmtp_client_rcpt_next(struct lmtp_client *client, const char *line)
{
	struct lmtp_rcpt *rcpt;
	bool success;

	success = line[0] == '2';
	if (success)
		client->rcpt_to_successes = TRUE;

	rcpt = array_idx_modifiable(&client->recipients,
				    client->rcpt_next_receive_idx);
	client->rcpt_next_receive_idx++;

	rcpt->failed = !success;
	rcpt->rcpt_to_callback(success, line, rcpt->context);
}

static int lmtp_client_send_data_cmd(struct lmtp_client *client)
{
	if (client->rcpt_next_receive_idx < array_count(&client->recipients))
		return 0;

	if (client->global_fail_string != NULL || !client->rcpt_to_successes) {
		lmtp_client_fail(client, client->global_fail_string);
		return -1;
	} else {
		client->input_state++;
		o_stream_nsend_str(client->output, "DATA\r\n");
		return 0;
	}
}

static int
lmtp_client_data_next(struct lmtp_client *client, const char *line)
{
	struct lmtp_rcpt *rcpt;
	unsigned int i, count;

	rcpt = array_get_modifiable(&client->recipients, &count);
	for (i = client->rcpt_next_data_idx; i < count; i++) {
		if (rcpt[i].failed) {
			/* already called rcpt_to_callback with failure */
			continue;
		}

		client->rcpt_next_data_idx = i + 1;
		rcpt[i].failed = line[0] != '2';
		rcpt[i].data_callback(!rcpt[i].failed, line, rcpt[i].context);
		if (client->protocol == LMTP_CLIENT_PROTOCOL_LMTP)
			break;
	}
	if (client->rcpt_next_data_idx < count)
		return 0;

	o_stream_send_str(client->output, "QUIT\r\n");
	lmtp_client_close(client);
	return -1;
}

static void lmtp_client_send_data(struct lmtp_client *client)
{
	const unsigned char *data;
	unsigned char add;
	size_t i, size;
	bool sent_bytes = FALSE;
	int ret;

	if (client->output_finished)
		return;

	while ((ret = i_stream_read_data(client->data_input,
					 &data, &size, 0)) > 0) {
		add = '\0';
		for (i = 0; i < size; i++) {
			if (data[i] == '\n') {
				if ((i == 0 && client->output_last != '\r') ||
				    (i > 0 && data[i-1] != '\r')) {
					/* missing CR */
					add = '\r';
					break;
				}
			} else if (data[i] == '.' &&
				   ((i == 0 && client->output_last == '\n') ||
				    (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				break;
			}
		}

		if (i > 0) {
			if (o_stream_send(client->output, data, i) < 0)
				break;
			client->output_last = data[i-1];
			i_stream_skip(client->data_input, i);
			sent_bytes = TRUE;
		}

		if (o_stream_get_buffer_used_size(client->output) >= 4096) {
			if ((ret = o_stream_flush(client->output)) < 0)
				break;
			if (ret == 0) {
				/* continue later */
				o_stream_set_flush_pending(client->output, TRUE);
				return;
			}
		}

		if (add != '\0') {
			if (o_stream_send(client->output, &add, 1) < 0)
				break;

			client->output_last = add;
		}
	}
	if (sent_bytes && client->data_output_callback != NULL)
		client->data_output_callback(client->data_output_context);

	if (ret == 0 || ret == -2) {
		/* -2 can happen with tee istreams */
		return;
	}

	if (client->output_last != '\n') {
		/* didn't end with CRLF */
		o_stream_nsend(client->output, "\r\n", 2);
	}
	o_stream_nsend(client->output, ".\r\n", 3);
	client->output_finished = TRUE;
}

static void lmtp_client_send_handshake(struct lmtp_client *client)
{
	switch (client->protocol) {
	case LMTP_CLIENT_PROTOCOL_LMTP:
		o_stream_nsend_str(client->output,
			t_strdup_printf("LHLO %s\r\n",
					client->set.my_hostname));
		break;
	case LMTP_CLIENT_PROTOCOL_SMTP:
		o_stream_nsend_str(client->output,
			t_strdup_printf("EHLO %s\r\n",
					client->set.my_hostname));
		break;
	}
}

static int lmtp_input_get_reply_code(const char *line, int *reply_code_r,
				     string_t *multiline)
{
	if (!i_isdigit(line[0]) || !i_isdigit(line[1]) || !i_isdigit(line[2]))
		return -1;

	*reply_code_r = (line[0]-'0') * 100 +
		(line[1]-'0') * 10 +
		(line[2]-'0');

	if (line[3] == ' ') {
		/* final reply */
		return 1;
	} else if (line[3] == '-') {
		/* multiline reply. */
		str_append(multiline, line);
		str_append_c(multiline, '\n');
		return 0;
	} else {
		/* invalid input */
		return -1;
	}
}

static void
lmtp_client_parse_capabilities(struct lmtp_client *client, const char *lines)
{
	const char *const *linep;

	for (linep = t_strsplit(lines, "\n"); *linep != NULL; linep++) {
		const char *line = *linep;

		line += 4; /* already checked this is valid */
		if (strncasecmp(line, "XCLIENT ", 8) == 0) {
			client->xclient_args =
				(void *)p_strsplit(client->pool, line + 8, " ");
		}
	}
}

static bool lmtp_client_send_xclient(struct lmtp_client *client)
{
	string_t *str;
	unsigned int empty_len;

	if (client->xclient_args == NULL) {
		/* not supported */
		return FALSE;
	}
	if (client->xclient_sent)
		return FALSE;

	str = t_str_new(64);
	str_append(str, "XCLIENT");
	empty_len = str_len(str);
	if (client->set.source_ip.family != 0 &&
	    str_array_icase_find(client->xclient_args, "ADDR"))
		str_printfa(str, " ADDR=%s", net_ip2addr(&client->set.source_ip));
	if (client->set.source_port != 0 &&
	    str_array_icase_find(client->xclient_args, "PORT"))
		str_printfa(str, " PORT=%u", client->set.source_port);
	if (client->set.proxy_ttl != 0 &&
	    str_array_icase_find(client->xclient_args, "TTL"))
		str_printfa(str, " TTL=%u", client->set.proxy_ttl);
	if (client->set.proxy_timeout_secs != 0 &&
	    str_array_icase_find(client->xclient_args, "TIMEOUT"))
		str_printfa(str, " TIMEOUT=%u", client->set.proxy_timeout_secs);

	if (str_len(str) == empty_len)
		return FALSE;

	str_append(str, "\r\n");
	o_stream_nsend(client->output, str_data(str), str_len(str));
	return TRUE;
}

static int lmtp_client_input_line(struct lmtp_client *client, const char *line)
{
	int ret, reply_code = 0;

	if ((ret = lmtp_input_get_reply_code(line, &reply_code,
					     client->input_multiline)) <= 0) {
		if (ret == 0)
			return 0;
		lmtp_client_fail(client, line);
		return -1;
	}

	switch (client->input_state) {
	case LMTP_INPUT_STATE_GREET:
	case LMTP_INPUT_STATE_XCLIENT:
		if (reply_code != 220) {
			lmtp_client_fail(client, line);
			return -1;
		}
		lmtp_client_send_handshake(client);
		client->input_state = LMTP_INPUT_STATE_LHLO;
		break;
	case LMTP_INPUT_STATE_LHLO:
	case LMTP_INPUT_STATE_MAIL_FROM:
		if (reply_code != 250) {
			lmtp_client_fail(client, line);
			return -1;
		}
		str_append(client->input_multiline, line);
		lmtp_client_parse_capabilities(client,
			str_c(client->input_multiline));
		if (client->input_state == LMTP_INPUT_STATE_LHLO &&
		    lmtp_client_send_xclient(client)) {
			client->input_state = LMTP_INPUT_STATE_XCLIENT;
			client->xclient_sent = TRUE;
			break;
		}
		if (client->input_state == LMTP_INPUT_STATE_LHLO) {
			o_stream_nsend_str(client->output,
				t_strdup_printf("MAIL FROM:%s\r\n",
						client->set.mail_from));
		}
		client->input_state++;
		lmtp_client_send_rcpts(client);
		break;
	case LMTP_INPUT_STATE_RCPT_TO:
		lmtp_client_rcpt_next(client, line);
		if (client->data_input == NULL)
			break;
		if (lmtp_client_send_data_cmd(client) < 0)
			return -1;
		break;
	case LMTP_INPUT_STATE_DATA_CONTINUE:
		/* Start sending DATA */
		if (strncmp(line, "354", 3) != 0) {
			lmtp_client_fail(client, line);
			return -1;
		}
		client->input_state++;
		if (client->data_header != NULL)
			o_stream_nsend_str(client->output, client->data_header);
		lmtp_client_send_data(client);
		break;
	case LMTP_INPUT_STATE_DATA:
		/* DATA replies */
		if (lmtp_client_data_next(client, line) < 0)
			return -1;
		break;
	}
	return 1;
}

static void lmtp_client_input(struct lmtp_client *client)
{
	const char *line;
	int ret;

	lmtp_client_ref(client);
	o_stream_cork(client->output);
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		T_BEGIN {
			ret = lmtp_client_input_line(client, line);
		} T_END;
		if (ret < 0) {
			o_stream_uncork(client->output);
			lmtp_client_unref(&client);
			return;
		}
		if (ret > 0)
			str_truncate(client->input_multiline, 0);
	}

	if (client->input->stream_errno == ENOBUFS) {
		lmtp_client_fail(client,
				 "501 5.5.4 Command reply line too long");
	} else if (client->input->stream_errno != 0) {
		errno = client->input->stream_errno;
		i_error("lmtp client: read() failed: %m");
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (read failure)");
	} else if (client->input->eof) {
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (disconnected in input)");
	}
	o_stream_uncork(client->output);
	lmtp_client_unref(&client);
}

static void lmtp_client_wait_connect(struct lmtp_client *client)
{
	int err;

	err = net_geterror(client->fd);
	if (err != 0) {
		i_error("lmtp client: connect(%s, %u) failed: %s",
			client->host, client->port, strerror(err));
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (connect)");
		return;
	}
	io_remove(&client->io);
	client->io = io_add(client->fd, IO_READ, lmtp_client_input, client);
	lmtp_client_input(client);
}

static int lmtp_client_output(struct lmtp_client *client)
{
	int ret;

	lmtp_client_ref(client);
	o_stream_cork(client->output);
	if ((ret = o_stream_flush(client->output)) < 0)
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (disconnected in output)");
	else if (client->input_state == LMTP_INPUT_STATE_DATA)
		lmtp_client_send_data(client);
	o_stream_uncork(client->output);
	lmtp_client_unref(&client);
	return ret;
}

static int lmtp_client_connect(struct lmtp_client *client)
{
	client->fd = net_connect_ip(&client->ip, client->port, NULL);
	if (client->fd == -1) {
		i_error("lmtp client: connect(%s, %u) failed: %m",
			client->host, client->port);
		return -1;
	}
	client->input =
		i_stream_create_fd(client->fd, LMTP_MAX_LINE_LEN, FALSE);
	client->output = o_stream_create_fd(client->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, lmtp_client_output, client);
	/* we're already sending data in ostream, so can't use IO_WRITE here */
	client->io = io_add(client->fd, IO_READ,
			    lmtp_client_wait_connect, client);
	return 0;
}

static void lmtp_client_dns_done(const struct dns_lookup_result *result,
				 struct lmtp_client *client)
{
	client->dns_lookup = NULL;

	if (result->ret != 0) {
		i_error("lmtp client: DNS lookup of %s failed: %s",
			client->host, result->error);
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (DNS lookup)");
	} else {
		client->ip = result->ips[0];
		if (lmtp_client_connect(client) < 0) {
			lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
					 " (connect)");
		}
	}
}

int lmtp_client_connect_tcp(struct lmtp_client *client,
			    enum lmtp_client_protocol protocol,
			    const char *host, unsigned int port)
{
	struct dns_lookup_settings dns_lookup_set;
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret;

	client->input_state = LMTP_INPUT_STATE_GREET;
	client->host = p_strdup(client->pool, host);
	client->port = port;
	client->protocol = protocol;

	if (*host == '\0') {
		i_error("lmtp client: host not given");
		return -1;
	}

	memset(&dns_lookup_set, 0, sizeof(dns_lookup_set));
	dns_lookup_set.dns_client_socket_path =
		client->set.dns_client_socket_path;
	dns_lookup_set.timeout_msecs = LMTP_CLIENT_DNS_LOOKUP_TIMEOUT_MSECS;

	if (net_addr2ip(host, &client->ip) == 0) {
		/* IP address */
	} else if (dns_lookup_set.dns_client_socket_path == NULL) {
		/* no dns-client, use blocking lookup */
		ret = net_gethostbyname(host, &ips, &ips_count);
		if (ret != 0) {
			i_error("lmtp client: DNS lookup of %s failed: %s",
				client->host, net_gethosterror(ret));
			return -1;
		}
		client->ip = ips[0];
	} else {
		if (dns_lookup(host, &dns_lookup_set,
			       lmtp_client_dns_done, client,
			       &client->dns_lookup) < 0)
			return -1;
		return 0;
	}

	if (lmtp_client_connect(client) < 0)
		return -1;
	return 0;
}

void lmtp_client_set_data_header(struct lmtp_client *client, const char *str)
{
	client->data_header = p_strdup(client->pool, str);
}

static void lmtp_client_send_rcpts(struct lmtp_client *client)
{
	const struct lmtp_rcpt *rcpt;
	unsigned int i, count;

	rcpt = array_get(&client->recipients, &count);
	for (i = client->rcpt_next_send_idx; i < count; i++) {
		o_stream_nsend_str(client->output,
			t_strdup_printf("RCPT TO:<%s>\r\n", rcpt[i].address));
	}
	client->rcpt_next_send_idx = i;
}

void lmtp_client_add_rcpt(struct lmtp_client *client, const char *address,
			  lmtp_callback_t *rcpt_to_callback,
			  lmtp_callback_t *data_callback, void *context)
{
	struct lmtp_rcpt *rcpt;

	rcpt = array_append_space(&client->recipients);
	rcpt->address = p_strdup(client->pool, address);
	rcpt->rcpt_to_callback = rcpt_to_callback;
	rcpt->data_callback = data_callback;
	rcpt->context = context;

	if (client->global_fail_string != NULL) {
		client->rcpt_next_receive_idx++;
		i_assert(client->rcpt_next_receive_idx ==
			 array_count(&client->recipients));

		rcpt->failed = TRUE;
		rcpt_to_callback(FALSE, client->global_fail_string, context);
	} else if (client->input_state == LMTP_INPUT_STATE_RCPT_TO)
		lmtp_client_send_rcpts(client);
}

void lmtp_client_send(struct lmtp_client *client, struct istream *data_input)
{
	i_stream_ref(data_input);
	client->data_input = data_input;

	(void)lmtp_client_send_data_cmd(client);
}

void lmtp_client_send_more(struct lmtp_client *client)
{
	if (client->input_state == LMTP_INPUT_STATE_DATA) {
		o_stream_cork(client->output);
		lmtp_client_send_data(client);
		o_stream_uncork(client->output);
	}
}

void lmtp_client_set_data_output_callback(struct lmtp_client *client,
					  void (*callback)(void *),
					  void *context)
{
	client->data_output_callback = callback;
	client->data_output_context = context;
}
