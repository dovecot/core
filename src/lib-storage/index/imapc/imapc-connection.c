/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "str.h"
#include "dns-lookup.h"
#include "imap-quote.h"
#include "imap-util.h"
#include "imap-parser.h"
#include "imapc-client-private.h"
#include "imapc-seqmap.h"
#include "imapc-connection.h"

#include <ctype.h>

#define IMAPC_DNS_LOOKUP_TIMEOUT_MSECS (1000*30)
#define IMAPC_CONNECT_TIMEOUT_MSECS (1000*30)

enum imapc_input_state {
	IMAPC_INPUT_STATE_NONE = 0,
	IMAPC_INPUT_STATE_UNTAGGED,
	IMAPC_INPUT_STATE_UNTAGGED_NUM,
	IMAPC_INPUT_STATE_TAGGED,
	IMAPC_INPUT_STATE_SKIPLINE
};

struct imapc_command {
	pool_t pool;
	buffer_t *data;
	unsigned int send_pos;
	unsigned int tag;

	imapc_command_callback_t *callback;
	void *context;
};

struct imapc_connection {
	struct imapc_client *client;
	char *name;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct imap_parser *parser;
	struct timeout *to;

	int (*input_callback)(struct imapc_connection *conn);
	enum imapc_input_state input_state;
	unsigned int cur_tag;
	uint32_t cur_num;

	struct imapc_client_mailbox *selecting_box, *selected_box;
	enum imapc_connection_state state;

	enum imapc_capability capabilities;
	char **capabilities_list;

	ARRAY_DEFINE(cmd_send_queue, struct imapc_command *);
	ARRAY_DEFINE(cmd_wait_list, struct imapc_command *);

	unsigned int ips_count, prev_connect_idx;
	struct ip_addr *ips;

	unsigned int idling:1;
	unsigned int idle_stopping:1;
	unsigned int idle_plus_waiting:1;
};

static void imapc_connection_disconnect(struct imapc_connection *conn);

static void imapc_command_send_more(struct imapc_connection *conn,
				    struct imapc_command *cmd);

struct imapc_connection *
imapc_connection_init(struct imapc_client *client)
{
	struct imapc_connection *conn;

	conn = i_new(struct imapc_connection, 1);
	conn->client = client;
	conn->fd = -1;
	conn->name = i_strdup_printf("%s:%u", client->set.host,
				     client->set.port);
	i_array_init(&conn->cmd_send_queue, 8);
	i_array_init(&conn->cmd_wait_list, 32);
	return conn;
}

void imapc_connection_deinit(struct imapc_connection **_conn)
{
	struct imapc_connection *conn = *_conn;

	*_conn = NULL;

	imapc_connection_disconnect(conn);
	p_strsplit_free(default_pool, conn->capabilities_list);
	array_free(&conn->cmd_send_queue);
	array_free(&conn->cmd_wait_list);
	i_free(conn->ips);
	i_free(conn->name);
	i_free(conn);
}

void imapc_connection_ioloop_changed(struct imapc_connection *conn)
{
	if (conn->io != NULL)
		conn->io = io_loop_move_io(&conn->io);
	if (conn->to != NULL)
		conn->to = io_loop_move_timeout(&conn->to);
}

static void imapc_connection_set_state(struct imapc_connection *conn,
				       enum imapc_connection_state state)
{
	if (state == IMAPC_CONNECTION_STATE_DISCONNECTED) {
		/* abort all pending commands */
		struct imapc_command_reply reply;
		struct imapc_command *const *cmdp, *cmd;

		memset(&reply, 0, sizeof(reply));
		reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;
		reply.text_without_resp = reply.text_full =
			"Disconnected from server";

		while (array_count(&conn->cmd_wait_list) > 0) {
			cmdp = array_idx(&conn->cmd_wait_list, 0);
			cmd = *cmdp;
			array_delete(&conn->cmd_wait_list, 0, 1);

			cmd->callback(&reply, cmd->context);
			pool_unref(&cmd->pool);
		}
		while (array_count(&conn->cmd_send_queue) > 0) {
			cmdp = array_idx(&conn->cmd_send_queue, 0);
			cmd = *cmdp;
			array_delete(&conn->cmd_send_queue, 0, 1);

			cmd->callback(&reply, cmd->context);
			pool_unref(&cmd->pool);
		}
	}
	if (state == IMAPC_CONNECTION_STATE_DONE) {
		if (array_count(&conn->cmd_send_queue) > 0) {
			struct imapc_command *const *cmd_p =
				array_idx(&conn->cmd_send_queue, 0);
			imapc_command_send_more(conn, *cmd_p);
		}
	}
	conn->state = state;
}

static void imapc_connection_disconnect(struct imapc_connection *conn)
{
	if (conn->fd == -1)
		return;

	if (conn->to != NULL)
		timeout_remove(&conn->to);
	imap_parser_destroy(&conn->parser);
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	net_disconnect(conn->fd);
	conn->fd = -1;

	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DISCONNECTED);
}

static void ATTR_FORMAT(2, 3)
imapc_connection_input_error(struct imapc_connection *conn,
			     const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i_error("imapc(%s): Server sent invalid input: %s",
		conn->name, t_strdup_vprintf(fmt, va));
	imapc_connection_disconnect(conn);
	va_end(va);
}

static int
imapc_connection_read_line(struct imapc_connection *conn,
			   const struct imap_arg **imap_args_r)
{
	int ret;
	bool fatal;

	ret = imap_parser_read_args(conn->parser, 0, 0, imap_args_r);
	if (ret == -2) {
		/* need more data */
		return 0;
	}
	if (ret < 0) {
		imapc_connection_input_error(conn, "Error parsing input: %s",
			imap_parser_get_error(conn->parser, &fatal));
		return -1;
	}
	return 1;
}

static int
imapc_connection_parse_capability(struct imapc_connection *conn,
				  const char *value)
{
	const char *const *tmp;
	unsigned int i;

	conn->capabilities = 0;
	if (conn->capabilities_list != NULL)
		p_strsplit_free(default_pool, conn->capabilities_list);
	conn->capabilities_list = p_strsplit(default_pool, value, " ");

	for (tmp = t_strsplit(value, " "); *tmp != NULL; tmp++) {
		for (i = 0; imapc_capability_names[i].name != NULL; i++) {
			const struct imapc_capability_name *cap =
				&imapc_capability_names[i];

			if (strcasecmp(*tmp, cap->name) == 0) {
				conn->capabilities |= cap->capability;
				break;
			}
		}
	}

	if ((conn->capabilities & IMAPC_CAPABILITY_IMAP4REV1) == 0) {
		imapc_connection_input_error(conn,
			"CAPABILITY list is missing IMAP4REV1");
		return -1;
	}
	return 0;
}

static int
imapc_connection_handle_resp_text_code(struct imapc_connection *conn,
				       const char *key, const char *value)
{
	if (strcasecmp(key, "CAPABILITY") == 0) {
		if (imapc_connection_parse_capability(conn, value) < 0)
			return -1;
	}
	if (strcasecmp(key, "CLOSED") == 0) {
		/* QRESYNC: SELECTing another mailbox */
		if (conn->selecting_box != NULL) {
			conn->selected_box = conn->selecting_box;
			conn->selecting_box = NULL;
		}
	}
	return 0;
}

static int
imapc_connection_handle_resp_text(struct imapc_connection *conn,
				  const char *text,
				  const char **key_r, const char **value_r)
{
	const char *p, *value;

	i_assert(text[0] == '[');

	p = strchr(text, ']');
	if (p == NULL) {
		imapc_connection_input_error(conn, "Missing ']' in resp-text");
		return -1;
	}
	text = t_strdup_until(text + 1, p);
	value = strchr(text, ' ');
	if (value != NULL) {
		*key_r = t_strdup_until(text, value);
		*value_r = value + 1;
	} else {
		*key_r = text;
		*value_r = NULL;
	}
	return 0;
}

static int
imapc_connection_handle_imap_resp_text(struct imapc_connection *conn,
				       const struct imap_arg *args,
				       const char **key_r, const char **value_r)
{
	const char *text;

	if (args->type != IMAP_ARG_ATOM)
		return 0;

	text = imap_args_to_str(args);
	if (*text != '[') {
		if (*text == '\0') {
			imapc_connection_input_error(conn,
				"Missing text in resp-text");
			return -1;
		}
		return 0;
	}
	if (imapc_connection_handle_resp_text(conn, text, key_r, value_r) < 0)
		return -1;

	return imapc_connection_handle_resp_text_code(conn, *key_r, *value_r);
}

static bool need_literal(const char *str)
{
	unsigned int i;

	for (i = 0; str[i] != '\0'; i++) {
		unsigned char c = str[i];

		if ((c & 0x80) != 0 || c == '\r' || c == '\n')
			return TRUE;
	}
	return FALSE;
}

static void imapc_connection_input_reset(struct imapc_connection *conn)
{
	conn->input_state = IMAPC_INPUT_STATE_NONE;
	conn->cur_tag = 0;
	conn->cur_num = 0;
	imap_parser_reset(conn->parser);
}

static int imapc_connection_skip_line(struct imapc_connection *conn)
{
	const unsigned char *data;
	size_t i, data_size;
	int ret = 0;

	data = i_stream_get_data(conn->input, &data_size);
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			imapc_connection_input_reset(conn);
			ret = 1;
			i++;
			break;
		}
	}
	i_stream_skip(conn->input, i);
	return ret;
}

static void
imapc_connection_capability_cb(const struct imapc_command_reply *reply,
			       void *context)
{
	struct imapc_connection *conn = context;

	if (reply->state != IMAPC_COMMAND_STATE_OK) {
		imapc_connection_input_error(conn,
			"Failed to get capabilities: %s", reply->text_full);
	} else if (conn->capabilities == 0) {
		imapc_connection_input_error(conn,
			"Capabilities not returned by server");
	} else {
		timeout_remove(&conn->to);
		imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DONE);
	}
}

static void imapc_connection_login_cb(const struct imapc_command_reply *reply,
				      void *context)
{
	struct imapc_connection *conn = context;

	if (reply->state != IMAPC_COMMAND_STATE_OK) {
		imapc_connection_input_error(conn, "Authentication failed: %s",
					     reply->text_full);
		return;
	}

	if (conn->capabilities == 0) {
		/* server didn't send capabilities automatically.
		   request them manually before we're done. */
		imapc_connection_cmd(conn, "CAPABILITY",
				     imapc_connection_capability_cb, conn);
		return;
	}

	timeout_remove(&conn->to);
	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DONE);
}

static const char *
imapc_connection_get_sasl_plain_request(struct imapc_connection *conn)
{
	const struct imapc_client_settings *set = &conn->client->set;
	string_t *in, *out;

	in = t_str_new(128);
	if (set->master_user != NULL) {
		str_append(in, set->username);
		str_append_c(in, '\0');
		str_append(in, set->master_user);
	} else {
		str_append_c(in, '\0');
		str_append(in, set->username);
	}
	str_append_c(in, '\0');
	str_append(in, set->password);

	out = t_str_new(128);
	base64_encode(in->data, in->used, out);
	return str_c(out);
}

static int imapc_connection_input_banner(struct imapc_connection *conn)
{
	const struct imapc_client_settings *set = &conn->client->set;
	const struct imap_arg *imap_args;
	const char *cmd, *key, *value;
	int ret;

	if ((ret = imapc_connection_read_line(conn, &imap_args)) <= 0)
		return ret;

	if (imapc_connection_handle_imap_resp_text(conn, imap_args,
						   &key, &value) < 0)
		return -1;
	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_AUTHENTICATING);

	if (set->master_user == NULL &&
	    need_literal(set->username) && need_literal(set->password)) {
		/* We can use LOGIN command */
		imapc_connection_cmdf(conn, imapc_connection_login_cb, conn,
				      "LOGIN %s %s",
				      set->username, set->password);
	} else if ((conn->capabilities & IMAPC_CAPABILITY_SASL_IR) != 0) {
		cmd = t_strdup_printf("AUTHENTICATE PLAIN %s",
			imapc_connection_get_sasl_plain_request(conn));
		imapc_connection_cmd(conn, cmd,
				     imapc_connection_login_cb, conn);
	} else {
		cmd = t_strdup_printf("AUTHENTICATE PLAIN\r\n%s",
			imapc_connection_get_sasl_plain_request(conn));
		imapc_connection_cmd(conn, cmd,
				     imapc_connection_login_cb, conn);
	}
	conn->input_callback = NULL;
	imapc_connection_input_reset(conn);
	return 1;
}

static int imapc_connection_input_untagged(struct imapc_connection *conn)
{
	const struct imap_arg *imap_args;
	const char *name;
	struct imapc_untagged_reply reply;
	int ret;

	if (conn->state == IMAPC_CONNECTION_STATE_CONNECTING) {
		/* input banner */
		name = imap_parser_read_word(conn->parser);
		if (name == NULL)
			return 0;

		if (strcasecmp(name, "OK") != 0) {
			imapc_connection_input_error(conn,
				"Banner doesn't begin with OK: %s", name);
			return -1;
		}
		conn->input_callback = imapc_connection_input_banner;
		return 1;
	}

	if ((ret = imapc_connection_read_line(conn, &imap_args)) <= 0)
		return ret;
	if (!imap_arg_get_atom(&imap_args[0], &name)) {
		imapc_connection_input_error(conn, "Invalid untagged reply");
		return -1;
	}
	imap_args++;

	if (conn->input_state == IMAPC_INPUT_STATE_UNTAGGED &&
	    str_to_uint32(name, &conn->cur_num) == 0) {
		/* <seq> <event> */
		conn->input_state = IMAPC_INPUT_STATE_UNTAGGED_NUM;
		if (!imap_arg_get_atom(&imap_args[0], &name)) {
			imapc_connection_input_error(conn,
						     "Invalid untagged reply");
			return -1;
		}
		imap_args++;
	}
	memset(&reply, 0, sizeof(reply));

	if (strcasecmp(name, "OK") == 0) {
		if (imapc_connection_handle_imap_resp_text(conn, imap_args,
						&reply.resp_text_key,
						&reply.resp_text_value) < 0)
			return -1;
	}

	reply.name = name;
	reply.num = conn->cur_num;
	reply.args = imap_args;
	if (conn->selected_box != NULL) {
		reply.untagged_box_context =
			conn->selected_box->untagged_box_context;
	}
	conn->client->untagged_callback(&reply, conn->client->untagged_context);
	if (imap_arg_atom_equals(imap_args, "EXPUNGE") &&
	    conn->selected_box != NULL) {
		/* keep track of expunge map internally */
		imapc_seqmap_expunge(conn->selected_box->seqmap, conn->cur_num);
	}
	imapc_connection_input_reset(conn);
	return 1;
}

static int imapc_connection_input_plus(struct imapc_connection *conn)
{
	struct imapc_command *const *cmd_p;

	if (conn->idle_plus_waiting) {
		/* "+ idling" reply for IDLE command */
		conn->idle_plus_waiting = FALSE;
		conn->idling = TRUE;
		return imapc_connection_skip_line(conn);
	}

	if (array_count(&conn->cmd_send_queue) == 0) {
		imapc_connection_input_error(conn, "Unexpected '+'");
		return -1;
	}
	cmd_p = array_idx(&conn->cmd_send_queue, 0);
	imapc_command_send_more(conn, *cmd_p);

	conn->input_state = IMAPC_INPUT_STATE_SKIPLINE;
	return imapc_connection_skip_line(conn);
}

static int imapc_connection_input_tagged(struct imapc_connection *conn)
{
	struct imapc_command *const *cmds, *cmd = NULL;
	unsigned int i, count;
	char *line, *linep;
	const char *p;
	struct imapc_command_reply reply;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return 0;

	memset(&reply, 0, sizeof(reply));

	linep = strchr(line, ' ');
	if (linep == NULL)
		reply.text_full = "";
	else {
		*linep = '\0';
		reply.text_full = linep + 1;
	}

	if (strcasecmp(line, "ok") == 0)
		reply.state = IMAPC_COMMAND_STATE_OK;
	else if (strcasecmp(line, "no") == 0)
		reply.state = IMAPC_COMMAND_STATE_NO;
	else if (strcasecmp(line, "bad") == 0) {
		i_error("imapc(%s): Command failed with BAD: %u %s",
			conn->name, conn->cur_tag, line);
		reply.state = IMAPC_COMMAND_STATE_BAD;
	} else {
		imapc_connection_input_error(conn,
			"Invalid state in tagged reply: %u %s",
			conn->cur_tag, line);
		return -1;
	}

	if (reply.text_full[0] == '[') {
		/* get resp-text */
		if (imapc_connection_handle_resp_text(conn, reply.text_full,
					&reply.resp_text_key,
					&reply.resp_text_value) < 0)
			return -1;

		p = strchr(reply.text_full, ']');
		i_assert(p != NULL);
		reply.text_without_resp = p + 1;
		if (reply.text_without_resp[0] == ' ')
			reply.text_without_resp++;
	} else {
		reply.text_without_resp = reply.text_full;
	}

	/* find the command. it's either the first command in send queue
	   (literal failed) or somewhere in wait list. */
	cmds = array_get(&conn->cmd_send_queue, &count);
	if (count > 0 && cmds[0]->tag == conn->cur_tag) {
		cmd = cmds[0];
		array_delete(&conn->cmd_send_queue, 0, 1);
	} else {
		cmds = array_get(&conn->cmd_wait_list, &count);
		for (i = 0; i < count; i++) {
			if (cmds[i]->tag == conn->cur_tag) {
				cmd = cmds[i];
				array_delete(&conn->cmd_wait_list, i, 1);
				break;
			}
		}
	}

	if (cmd == NULL) {
		imapc_connection_input_error(conn,
			"Unknown tag in a reply: %u %s", conn->cur_tag, line);
		return -1;
	}

	imapc_connection_input_reset(conn);
	cmd->callback(&reply, cmd->context);
	pool_unref(&cmd->pool);
	return 0;
}

static int imapc_connection_input_one(struct imapc_connection *conn)
{
	const char *tag;
	int ret = -1;

	if (conn->input_callback != NULL)
		return conn->input_callback(conn);

	switch (conn->input_state) {
	case IMAPC_INPUT_STATE_NONE:
		tag = imap_parser_read_word(conn->parser);
		if (tag == NULL)
			return 0;

		if (strcmp(tag, "") == 0) {
			/* FIXME: why do we get here.. */
			conn->input_state = IMAPC_INPUT_STATE_SKIPLINE;
			return imapc_connection_skip_line(conn);
		} else if (strcmp(tag, "*") == 0) {
			conn->input_state = IMAPC_INPUT_STATE_UNTAGGED;
			conn->cur_num = 0;
			ret = imapc_connection_input_untagged(conn);
		} else if (strcmp(tag, "+") == 0) {
			ret = imapc_connection_input_plus(conn);
		} else {
			conn->input_state = IMAPC_INPUT_STATE_TAGGED;
			if (str_to_uint(tag, &conn->cur_tag) < 0 ||
			    conn->cur_tag == 0) {
				imapc_connection_input_error(conn,
					"Invalid command tag: %s", tag);
				ret = -1;
			} else {
				ret = imapc_connection_input_tagged(conn);
			}
		}
		break;
	case IMAPC_INPUT_STATE_UNTAGGED:
	case IMAPC_INPUT_STATE_UNTAGGED_NUM:
		ret = imapc_connection_input_untagged(conn);
		break;
	case IMAPC_INPUT_STATE_TAGGED:
		ret = imapc_connection_input_tagged(conn);
		break;
	case IMAPC_INPUT_STATE_SKIPLINE:
		ret = imapc_connection_skip_line(conn);
		break;
	}
	return ret;
}

static void imapc_connection_input(struct imapc_connection *conn)
{
	int ret;

	if (i_stream_read(conn->input) == -1) {
		/* disconnected */
		i_error("imapc(%s): Server disconnected unexpectedly",
			conn->name);
		imapc_connection_disconnect(conn);
		return;
	}

	o_stream_cork(conn->output);
	do {
		T_BEGIN {
			ret = imapc_connection_input_one(conn);
		} T_END;
	} while (ret > 0);

	if (conn->output != NULL)
		o_stream_uncork(conn->output);
}

static void imapc_connection_connected(struct imapc_connection *conn)
{
	const struct ip_addr *ip = &conn->ips[conn->prev_connect_idx];
	int err;

	err = net_geterror(conn->fd);
	if (err != 0) {
		i_error("imapc(%s): connect(%s, %u) failed: %s",
			conn->name, net_ip2addr(ip), conn->client->set.port,
			strerror(err));
		imapc_connection_disconnect(conn);
		return;
	}
	io_remove(&conn->io);
	conn->io = io_add(conn->fd, IO_READ, imapc_connection_input, conn);
}

static void imapc_connection_timeout(struct imapc_connection *conn)
{
	const struct ip_addr *ip = &conn->ips[conn->prev_connect_idx];

	switch (conn->state) {
	case IMAPC_CONNECTION_STATE_CONNECTING:
		i_error("imapc(%s): connect(%s, %u) timed out after %u seconds",
			conn->name, net_ip2addr(ip), conn->client->set.port,
			IMAPC_CONNECT_TIMEOUT_MSECS/1000);
		break;
	case IMAPC_CONNECTION_STATE_AUTHENTICATING:
		i_error("imapc(%s): Authentication timed out after %u seconds",
			conn->name, IMAPC_CONNECT_TIMEOUT_MSECS/1000);
		break;
	default:
		i_unreached();
	}
	imapc_connection_disconnect(conn);
}

static void imapc_connection_connect_next_ip(struct imapc_connection *conn)
{
	int fd;

	conn->prev_connect_idx = (conn->prev_connect_idx+1) % conn->ips_count;
	fd = net_connect_ip(&conn->ips[conn->prev_connect_idx],
			    conn->client->set.port, NULL);
	if (fd == -1) {
		imapc_connection_set_state(conn,
			IMAPC_CONNECTION_STATE_DISCONNECTED);
		return;
	}
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_WRITE, imapc_connection_connected, conn);
	conn->parser = imap_parser_create(conn->input, NULL, (size_t)-1);
	conn->to = timeout_add(IMAPC_CONNECT_TIMEOUT_MSECS,
			       imapc_connection_timeout, conn);
}

static void
imapc_connection_dns_callback(const struct dns_lookup_result *result,
			      void *context)
{
	struct imapc_connection *conn = context;

	if (result->ret != 0) {
		i_error("imapc(%s): dns_lookup(%s) failed: %s",
			conn->name, conn->client->set.host, result->error);
		imapc_connection_set_state(conn,
			IMAPC_CONNECTION_STATE_DISCONNECTED);
		return;
	}

	i_assert(result->ips_count > 0);
	conn->ips_count = result->ips_count;
	conn->ips = i_new(struct ip_addr, conn->ips_count);
	memcpy(conn->ips, result->ips, sizeof(*conn->ips) * conn->ips_count);
	conn->prev_connect_idx = conn->ips_count - 1;

	imapc_connection_connect_next_ip(conn);
}

void imapc_connection_connect(struct imapc_connection *conn)
{
	struct dns_lookup_settings dns_set;

	if (conn->fd != -1)
		return;

	memset(&dns_set, 0, sizeof(dns_set));
	dns_set.dns_client_socket_path =
		conn->client->set.dns_client_socket_path;
	dns_set.timeout_msecs = IMAPC_DNS_LOOKUP_TIMEOUT_MSECS;

	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_CONNECTING);
	if (conn->ips_count == 0) {
		(void)dns_lookup(conn->client->set.host, &dns_set,
				 imapc_connection_dns_callback, conn);
	} else {
		imapc_connection_connect_next_ip(conn);
	}
}

static struct imapc_command *
imapc_command_begin(imapc_command_callback_t *callback, void *context)
{
	static unsigned int cmd_tag_counter = 0;
	struct imapc_command *cmd;
	pool_t pool;

	pool = pool_alloconly_create("imapc command", 1024);
	cmd = p_new(pool, struct imapc_command, 1);
	cmd->pool = pool;
	cmd->callback = callback;
	cmd->context = context;

	if (++cmd_tag_counter == 0)
		cmd_tag_counter++;
	cmd->tag = cmd_tag_counter;
	return cmd;
}

static bool
parse_sync_literal(const unsigned char *data, unsigned int pos,
		   unsigned int *value_r)
{
	unsigned int value = 0, mul = 1;

	/* data should contain "{size}\r\n" and pos points after \n */
	if (pos <= 4 || data[pos-1] != '\n' || data[pos-2] != '\r' ||
	    data[pos-3] != '}' || !i_isdigit(data[pos-4]))
		return FALSE;
	pos -= 4;

	do {
		value += (data[pos] - '0') * mul;
		mul = mul*10;
		pos--;
	} while (pos > 0 && i_isdigit(data[pos]));

	if (pos == 0 || data[pos] != '{')
		return FALSE;

	*value_r = value;
	return TRUE;
}

static void imapc_command_send_more(struct imapc_connection *conn,
				    struct imapc_command *cmd)
{
	const unsigned char *p;
	unsigned int seek_pos, start_pos, end_pos, size;

	i_assert(cmd->send_pos < cmd->data->used);

	seek_pos = cmd->send_pos;
	if (seek_pos != 0) {
		/* skip over the literal. we can also get here from
		   AUTHENTICATE command, which doesn't use a literal */
		if (parse_sync_literal(cmd->data->data, seek_pos, &size)) {
			seek_pos += size;
			i_assert(seek_pos <= cmd->data->used);
		}
	}

	do {
		start_pos = seek_pos;
		p = memchr(CONST_PTR_OFFSET(cmd->data->data, seek_pos), '\n',
			   cmd->data->used - seek_pos);
		i_assert(p != NULL);

		seek_pos = p - (const unsigned char *)cmd->data->data + 1;
		/* keep going for LITERAL+ command */
	} while (start_pos + 3 < seek_pos &&
		 p[-1] == '\r' && p[-2] == '}' && p[-3] == '+');
	end_pos = seek_pos;

	o_stream_send(conn->output,
		      CONST_PTR_OFFSET(cmd->data->data, cmd->send_pos),
		      end_pos - cmd->send_pos);
	cmd->send_pos = end_pos;

	if (cmd->send_pos == cmd->data->used) {
		/* everything sent. move command to wait list. */
		i_assert(*array_idx(&conn->cmd_send_queue, 0) == cmd);
		array_delete(&conn->cmd_send_queue, 0, 1);
		array_append(&conn->cmd_wait_list, &cmd, 1);

		if (array_count(&conn->cmd_send_queue) > 0 &&
		    conn->state == IMAPC_CONNECTION_STATE_DONE) {
			/* send the next command in queue */
			struct imapc_command *const *cmd2_p =
				array_idx(&conn->cmd_send_queue, 0);
			imapc_command_send_more(conn, *cmd2_p);
		}
	}
}

static void imapc_command_send(struct imapc_connection *conn,
			       struct imapc_command *cmd)
{
	if ((conn->idling || conn->idle_plus_waiting) && !conn->idle_stopping) {
		conn->idle_stopping = TRUE;
		o_stream_send_str(conn->output, "DONE\r\n");
	}
	switch (conn->state) {
	case IMAPC_CONNECTION_STATE_AUTHENTICATING:
		array_insert(&conn->cmd_send_queue, 0, &cmd, 1);
		imapc_command_send_more(conn, cmd);
		break;
	case IMAPC_CONNECTION_STATE_DONE:
		array_append(&conn->cmd_send_queue, &cmd, 1);
		if (array_count(&conn->cmd_send_queue) == 1)
			imapc_command_send_more(conn, cmd);
		break;
	default:
		array_append(&conn->cmd_send_queue, &cmd, 1);
		break;
	}
}

void imapc_connection_cmd(struct imapc_connection *conn, const char *cmdline,
			  imapc_command_callback_t *callback, void *context)
{
	struct imapc_command *cmd;
	unsigned int len = strlen(cmdline);

	cmd = imapc_command_begin(callback, context);
	cmd->data = str_new(cmd->pool, len + 2);
	str_printfa(cmd->data, "%u %s\r\n", cmd->tag, cmdline);
	imapc_command_send(conn, cmd);
}

void imapc_connection_cmdf(struct imapc_connection *conn,
			   imapc_command_callback_t *callback, void *context,
			   const char *cmd_fmt, ...)
{
	va_list args;

	va_start(args, cmd_fmt);
	imapc_connection_cmdvf(conn, callback, context, cmd_fmt, args);
	va_end(args);
}

void imapc_connection_cmdvf(struct imapc_connection *conn,
			   imapc_command_callback_t *callback, void *context,
			   const char *cmd_fmt, va_list args)
{
	struct imapc_command *cmd;
	unsigned int i;

	cmd = imapc_command_begin(callback, context);
	cmd->data = str_new(cmd->pool, 128);
	str_printfa(cmd->data, "%u ", cmd->tag);

	for (i = 0; cmd_fmt[i] != '\0'; i++) {
		if (cmd_fmt[i] != '%') {
			str_append_c(cmd->data, cmd_fmt[i]);
			continue;
		}

		switch (cmd_fmt[++i]) {
		case '\0':
			i_unreached();
		case 'u': {
			unsigned int arg = va_arg(args, unsigned int);

			str_printfa(cmd->data, "%u", arg);
			break;
		}
		case 's': {
			const char *arg = va_arg(args, const char *);

			if (!need_literal(arg))
				imap_dquote_append(cmd->data, arg);
			else if ((conn->capabilities &
				  IMAPC_CAPABILITY_LITERALPLUS) != 0) {
				str_printfa(cmd->data, "{%"PRIuSIZE_T"+}\r\n%s",
					    strlen(arg), arg);
			} else {
				str_printfa(cmd->data, "{%"PRIuSIZE_T"}\r\n%s",
					    strlen(arg), arg);
			}
			break;
		}
		case '1': {
			/* %1s - no quoting */
			const char *arg = va_arg(args, const char *);

			i_assert(cmd_fmt[++i] == 's');
			str_append(cmd->data, arg);
			break;
		}
		}
	}
	str_append(cmd->data, "\r\n");

	imapc_command_send(conn, cmd);
}

enum imapc_connection_state
imapc_connection_get_state(struct imapc_connection *conn)
{
	return conn->state;
}

enum imapc_capability
imapc_connection_get_capabilities(struct imapc_connection *conn)
{
	return conn->capabilities;
}

void imapc_connection_select(struct imapc_client_mailbox *box, const char *name,
			     imapc_command_callback_t *callback, void *context)
{
	struct imapc_connection *conn = box->conn;

	i_assert(conn->selecting_box == NULL);

	if (conn->selected_box != NULL &&
	    (conn->capabilities & IMAPC_CAPABILITY_QRESYNC) != 0) {
		/* server will send a [CLOSED] once selected mailbox is
		   closed */
		conn->selecting_box = box;
	} else {
		/* we'll have to assume that all the future untagged messages
		   are for the mailbox we're selecting */
		conn->selected_box = box;
	}

	imapc_connection_cmdf(conn, callback, context, "SELECT %s", name);
}

void imapc_connection_unselect(struct imapc_client_mailbox *box)
{
	i_assert(box->conn->selected_box == box ||
		 box->conn->selecting_box == box);

	box->conn->selected_box = NULL;
	box->conn->selecting_box = NULL;
}

static void
imapc_connection_idle_callback(const struct imapc_command_reply *reply ATTR_UNUSED,
			       void *context)
{
	struct imapc_connection *conn = context;

	conn->idling = FALSE;
	conn->idle_plus_waiting = FALSE;
	conn->idle_stopping = FALSE;
}

void imapc_connection_idle(struct imapc_connection *conn)
{
	if (array_count(&conn->cmd_send_queue) != 0 ||
	    array_count(&conn->cmd_wait_list) != 0 ||
	    conn->idling || conn->idle_plus_waiting ||
	    (conn->capabilities & IMAPC_CAPABILITY_IDLE) == 0)
		return;

	imapc_connection_cmd(conn, "IDLE",
			     imapc_connection_idle_callback, conn);
	conn->idle_plus_waiting = TRUE;
}
