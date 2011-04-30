/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
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
	LMTP_INPUT_STATE_DATA
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

	struct istream *input;
	struct ostream *output;
	struct io *io;
	int fd;

	void (*data_output_callback)(void *);
	void *data_output_context;

	lmtp_finish_callback_t *finish_callback;
	void *finish_context;

	const char *data_header;
	ARRAY_DEFINE(recipients, struct lmtp_rcpt);
	unsigned int rcpt_next_receive_idx;
	unsigned int rcpt_next_data_idx;
	unsigned int rcpt_next_send_idx;
	struct istream *data_input;
	unsigned char output_last;

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
	client->finish_callback = finish_callback;
	client->finish_context = context;
	client->fd = -1;
	p_array_init(&client->recipients, pool, 16);
	return client;
}

void lmtp_client_close(struct lmtp_client *client)
{
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->input != NULL)
		i_stream_unref(&client->input);
	if (client->output != NULL)
		o_stream_unref(&client->output);
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
	pool_ref(client->pool);
}

static void lmtp_client_unref(struct lmtp_client **_client)
{
	struct lmtp_client *client = *_client;

	*_client = NULL;
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
		return "DATA";
	case LMTP_INPUT_STATE_DATA:
		return "end-of-DATA";
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
		o_stream_send_str(client->output, "DATA\r\n");
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
	if (i < count)
		return 0;

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
		(void)o_stream_send(client->output, "\r\n", 2);
	}
	(void)o_stream_send(client->output, ".\r\n", 3);
	client->output_finished = TRUE;
}

static void lmtp_client_send_handshake(struct lmtp_client *client)
{
	o_stream_cork(client->output);
	switch (client->protocol) {
	case LMTP_CLIENT_PROTOCOL_LMTP:
		o_stream_send_str(client->output,
			t_strdup_printf("LHLO %s\r\n",
					client->set.my_hostname));
		break;
	case LMTP_CLIENT_PROTOCOL_SMTP:
		o_stream_send_str(client->output,
			t_strdup_printf("EHLO %s\r\n",
					client->set.my_hostname));
		break;
	}
	o_stream_send_str(client->output,
		t_strdup_printf("MAIL FROM:%s\r\n", client->set.mail_from));
	o_stream_uncork(client->output);
}

static int lmtp_input_get_reply_code(const char *line, int *reply_code_r)
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
		/* multiline reply. just ignore it. */
		return 0;
	} else {
		/* invalid input */
		return -1;
	}
}

static int lmtp_client_input_line(struct lmtp_client *client, const char *line)
{
	int ret, reply_code = 0;

	if ((ret = lmtp_input_get_reply_code(line, &reply_code)) <= 0) {
		if (ret == 0)
			return 0;
		lmtp_client_fail(client, line);
		return -1;
	}

	switch (client->input_state) {
	case LMTP_INPUT_STATE_GREET:
		if (reply_code != 220) {
			lmtp_client_fail(client, line);
			return -1;
		}
		lmtp_client_send_handshake(client);
		client->input_state++;
		break;
	case LMTP_INPUT_STATE_LHLO:
	case LMTP_INPUT_STATE_MAIL_FROM:
		if (reply_code != 250) {
			lmtp_client_fail(client, line);
			return -1;
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
		o_stream_cork(client->output);
		if (client->data_header != NULL)
			o_stream_send_str(client->output, client->data_header);
		lmtp_client_send_data(client);
		o_stream_uncork(client->output);
		break;
	case LMTP_INPUT_STATE_DATA:
		/* DATA replies */
		if (lmtp_client_data_next(client, line) < 0)
			return -1;
		break;
	}
	return 0;
}

static void lmtp_client_input(struct lmtp_client *client)
{
	const char *line;

	lmtp_client_ref(client);
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (lmtp_client_input_line(client, line) < 0) {
			lmtp_client_unref(&client);
			return;
		}
	}

	if (client->input->stream_errno != 0) {
		errno = client->input->stream_errno;
		i_error("lmtp client: read() failed: %m");
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (read failure)");
	} else if (client->input->eof) {
		lmtp_client_fail(client, ERRSTR_TEMP_REMOTE_FAILURE
				 " (disconnected in input)");
	}
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
	o_stream_set_flush_callback(client->output, lmtp_client_output, client);
	/* we're already sending data in ostream, so can't use IO_WRITE here */
	client->io = io_add(client->fd, IO_READ,
			    lmtp_client_wait_connect, client);
	return 0;
}

static void lmtp_client_dns_done(const struct dns_lookup_result *result,
				 struct lmtp_client *client)
{
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

	if (net_addr2ip(host, &client->ip) < 0) {
		if (dns_lookup(host, &dns_lookup_set,
			       lmtp_client_dns_done, client) < 0)
			return -1;
	} else {
		if (lmtp_client_connect(client) < 0)
			return -1;
	}
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
		o_stream_send_str(client->output,
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
	if (client->input_state == LMTP_INPUT_STATE_DATA)
		lmtp_client_send_data(client);
}

void lmtp_client_set_data_output_callback(struct lmtp_client *client,
					  void (*callback)(void *),
					  void *context)
{
	client->data_output_callback = callback;
	client->data_output_context = context;
}
