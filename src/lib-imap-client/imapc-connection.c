/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "write-full.h"
#include "str.h"
#include "time-util.h"
#include "dns-lookup.h"
#include "dsasl-client.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "imap-quote.h"
#include "imap-util.h"
#include "imap-parser.h"
#include "imapc-client-private.h"
#include "imapc-connection.h"

#include <unistd.h>
#include <ctype.h>

#define IMAPC_COMMAND_STATE_AUTHENTICATE_CONTINUE 10000
#define IMAPC_MAX_INLINE_LITERAL_SIZE (1024*32)
/* If LOGOUT reply takes longer than this, disconnect. */
#define IMAPC_LOGOUT_TIMEOUT_MSECS 5000

enum imapc_input_state {
	IMAPC_INPUT_STATE_NONE = 0,
	IMAPC_INPUT_STATE_PLUS,
	IMAPC_INPUT_STATE_UNTAGGED,
	IMAPC_INPUT_STATE_UNTAGGED_NUM,
	IMAPC_INPUT_STATE_TAGGED
};

struct imapc_command_stream {
	unsigned int pos;
	uoff_t size;
	struct istream *input;
};

struct imapc_command {
	pool_t pool;
	buffer_t *data;
	unsigned int send_pos;
	unsigned int tag;

	enum imapc_command_flags flags;
	struct imapc_connection *conn;
	/* If non-NULL, points to the mailbox where this command should be
	   executed */
	struct imapc_client_mailbox *box;

	ARRAY(struct imapc_command_stream) streams;

	imapc_command_callback_t *callback;
	void *context;

	/* This is the AUTHENTICATE command */
	bool authenticate:1;
	/* This is the IDLE command */
	bool idle:1;
	/* Waiting for '+' literal reply before we can continue */
	bool wait_for_literal:1;
	/* Command is fully sent to server */
	bool sent:1;
};
ARRAY_DEFINE_TYPE(imapc_command, struct imapc_command *);

struct imapc_connection_literal {
	char *temp_path;
	int fd;
	uoff_t bytes_left;

	const struct imap_arg *parent_arg;
	unsigned int list_idx;
};

struct imapc_connection {
	struct imapc_client *client;
	char *name;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input, *raw_input;
	struct ostream *output, *raw_output;
	struct imap_parser *parser;
	struct timeout *to;
	struct timeout *to_output;
	struct dns_lookup *dns_lookup;
	struct dsasl_client *sasl_client;

	struct ssl_iostream *ssl_iostream;

	int (*input_callback)(struct imapc_connection *conn);
	enum imapc_input_state input_state;
	unsigned int cur_tag;
	uint32_t cur_num;
	struct timeval last_connect;
	unsigned int reconnect_count;

	struct imapc_client_mailbox *selecting_box, *selected_box;
	enum imapc_connection_state state;
	char *disconnect_reason;

	enum imapc_capability capabilities;
	char **capabilities_list;

	imapc_command_callback_t *login_callback;
	void *login_context;

	/* commands pending in queue to be sent */
	ARRAY_TYPE(imapc_command) cmd_send_queue;
	/* commands that have been sent, waiting for their tagged reply */
	ARRAY_TYPE(imapc_command) cmd_wait_list;
	/* commands that were already sent, but were aborted since (due to
	   unselecting mailbox). */
	ARRAY_TYPE(seq_range) aborted_cmd_tags;
	unsigned int reconnect_command_count;

	unsigned int ips_count, prev_connect_idx;
	struct ip_addr *ips;

	struct imapc_connection_literal literal;
	ARRAY(struct imapc_arg_file) literal_files;

	unsigned int throttle_msecs;
	unsigned int throttle_shrink_msecs;
	unsigned int last_successful_throttle_msecs;
	bool throttle_pending;
	struct timeval throttle_end_timeval;
	struct timeout *to_throttle, *to_throttle_shrink;

	bool reconnecting:1;
	bool reconnect_waiting:1;
	bool reconnect_ok:1;
	bool idling:1;
	bool idle_stopping:1;
	bool idle_plus_waiting:1;
	bool select_waiting_reply:1;
};

static void imapc_connection_capability_cb(const struct imapc_command_reply *reply,
					   void *context);
static int imapc_connection_output(struct imapc_connection *conn);
static int imapc_connection_ssl_init(struct imapc_connection *conn);
static void imapc_command_free(struct imapc_command *cmd);
static void imapc_command_send_more(struct imapc_connection *conn);
static void
imapc_login_callback(struct imapc_connection *conn,
		     const struct imapc_command_reply *reply);

static void
imapc_auth_ok(struct imapc_connection *conn)
{
	if (conn->client->set.debug)
		i_debug("imapc(%s): Authenticated successfully", conn->name);

	if (conn->client->state_change_callback == NULL)
		return;

	conn->client->state_change_callback(conn->client->state_change_context,
					    IMAPC_STATE_CHANGE_AUTH_OK, NULL);
}

static void
imapc_auth_failed(struct imapc_connection *conn, const struct imapc_command_reply *_reply,
		  const char *error)
{
	struct imapc_command_reply reply = *_reply;

	if (reply.state != IMAPC_COMMAND_STATE_DISCONNECTED)
		reply.state = IMAPC_COMMAND_STATE_AUTH_FAILED;
	reply.text_without_resp = reply.text_full =
		t_strdup_printf("Authentication failed: %s", error);
	i_error("imapc(%s): %s", conn->name, reply.text_full);
	imapc_login_callback(conn, &reply);

	if (conn->client->state_change_callback == NULL)
		return;

	conn->client->state_change_callback(conn->client->state_change_context,
					    IMAPC_STATE_CHANGE_AUTH_FAILED,
					    error);
}

struct imapc_connection *
imapc_connection_init(struct imapc_client *client,
		      imapc_command_callback_t *login_callback,
		      void *login_context)
{
	struct imapc_connection *conn;

	conn = i_new(struct imapc_connection, 1);
	conn->refcount = 1;
	conn->client = client;
	conn->login_callback = login_callback;
	conn->login_context = login_context;
	conn->fd = -1;
	conn->name = i_strdup_printf("%s:%u", client->set.host,
				     client->set.port);
	conn->literal.fd = -1;
	conn->reconnect_ok = (client->set.connect_retry_count>0);
	i_array_init(&conn->cmd_send_queue, 8);
	i_array_init(&conn->cmd_wait_list, 32);
	i_array_init(&conn->literal_files, 4);
	i_array_init(&conn->aborted_cmd_tags, 8);

	if (client->set.debug)
		i_debug("imapc(%s): Created new connection", conn->name);

	imapc_client_ref(client);
	return conn;
}

static void imapc_connection_ref(struct imapc_connection *conn)
{
	i_assert(conn->refcount > 0);

	conn->refcount++;
}

static void imapc_connection_unref(struct imapc_connection **_conn)
{
	struct imapc_connection *conn = *_conn;

	i_assert(conn->refcount > 0);

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	i_assert(conn->disconnect_reason == NULL);

	if (conn->capabilities_list != NULL)
		p_strsplit_free(default_pool, conn->capabilities_list);
	array_free(&conn->cmd_send_queue);
	array_free(&conn->cmd_wait_list);
	array_free(&conn->literal_files);
	array_free(&conn->aborted_cmd_tags);
	imapc_client_unref(&conn->client);
	i_free(conn->ips);
	i_free(conn->name);
	i_free(conn);
}

void imapc_connection_deinit(struct imapc_connection **_conn)
{
	imapc_connection_disconnect(*_conn);
	imapc_connection_unref(_conn);
}

void imapc_connection_ioloop_changed(struct imapc_connection *conn)
{
	if (conn->io != NULL)
		conn->io = io_loop_move_io(&conn->io);
	if (conn->to != NULL)
		conn->to = io_loop_move_timeout(&conn->to);
	if (conn->to_throttle != NULL)
		conn->to_throttle = io_loop_move_timeout(&conn->to_throttle);
	if (conn->to_throttle_shrink != NULL)
		conn->to_throttle_shrink = io_loop_move_timeout(&conn->to_throttle_shrink);
	if (conn->output != NULL)
		o_stream_switch_ioloop(conn->output);
	if (conn->dns_lookup != NULL)
		dns_lookup_switch_ioloop(conn->dns_lookup);

	if (conn->client->ioloop == NULL && conn->to_output != NULL) {
		/* we're only once moving the to_output to the main ioloop,
		   since timeout moves currently also reset the timeout.
		   (the rest of the times this is a no-op) */
		conn->to_output = io_loop_move_timeout(&conn->to_output);
	}
}

static const char *imapc_command_get_readable(struct imapc_command *cmd)
{
	string_t *str = t_str_new(256);
	const unsigned char *data = cmd->data->data;
	unsigned int i;

	for (i = 0; i < cmd->data->used; i++) {
		if (data[i] != '\r' && data[i] != '\n')
			str_append_c(str, data[i]);
	}
	return str_c(str);
}

static void
imapc_connection_abort_commands_array(ARRAY_TYPE(imapc_command) *cmd_array,
				      ARRAY_TYPE(imapc_command) *dest_array,
				      struct imapc_client_mailbox *only_box,
				      bool keep_retriable)
{
	struct imapc_command *const *cmdp, *cmd;
	unsigned int i;

	for (i = 0; i < array_count(cmd_array); ) {
		cmdp = array_idx(cmd_array, i);
		cmd = *cmdp;

		if (cmd->box != only_box && only_box != NULL)
			i++;
		else if (keep_retriable &&
			 (cmd->flags & IMAPC_COMMAND_FLAG_RETRIABLE) != 0) {
			cmd->send_pos = 0;
			cmd->wait_for_literal = 0;
			cmd->flags |= IMAPC_COMMAND_FLAG_RECONNECTED;
			i++;
		} else {
			array_delete(cmd_array, i, 1);
			array_push_back(dest_array, &cmd);
		}
	}
}

void imapc_connection_abort_commands(struct imapc_connection *conn,
				     struct imapc_client_mailbox *only_box,
				     bool keep_retriable)
{
	struct imapc_command *const *cmdp, *cmd;
	ARRAY_TYPE(imapc_command) tmp_array;
	struct imapc_command_reply reply;

	t_array_init(&tmp_array, 8);
	imapc_connection_abort_commands_array(&conn->cmd_wait_list, &tmp_array,
					      only_box, keep_retriable);
	imapc_connection_abort_commands_array(&conn->cmd_send_queue, &tmp_array,
					      only_box, keep_retriable);

	if (array_count(&conn->cmd_wait_list) > 0 && only_box == NULL) {
		/* need to move all the waiting commands to send queue */
		array_append_array(&conn->cmd_wait_list,
				   &conn->cmd_send_queue);
		array_clear(&conn->cmd_send_queue);
		array_append_array(&conn->cmd_send_queue,
				   &conn->cmd_wait_list);
		array_clear(&conn->cmd_wait_list);
	}

	/* abort the commands. we'll do it here later so that if the
	   callback recurses us back here we don't crash */
	i_zero(&reply);
	reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;
	if (only_box != NULL) {
		reply.text_without_resp = reply.text_full =
			"Unselecting mailbox";
	} else {
		reply.text_without_resp = reply.text_full =
			"Disconnected from server";
	}
	array_foreach(&tmp_array, cmdp) {
		cmd = *cmdp;

		if (cmd->sent && conn->state == IMAPC_CONNECTION_STATE_DONE) {
			/* We're not disconnected, so the reply will still
			   come. Remember that it needs to be ignored. */
			seq_range_array_add(&conn->aborted_cmd_tags, cmd->tag);
		}
		cmd->callback(&reply, cmd->context);
		imapc_command_free(cmd);
	}
	timeout_remove(&conn->to);
}

static void
imapc_login_callback(struct imapc_connection *conn,
		     const struct imapc_command_reply *reply)
{
	if (conn->login_callback != NULL)
		conn->login_callback(reply, conn->login_context);
}

static void imapc_connection_set_state(struct imapc_connection *conn,
				       enum imapc_connection_state state)
{
	struct imapc_command_reply reply;

	conn->state = state;

	switch (state) {
	case IMAPC_CONNECTION_STATE_DISCONNECTED:
		i_zero(&reply);
		reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;
		reply.text_full = "Disconnected from server";
		if (conn->disconnect_reason != NULL) {
			reply.text_full = t_strdup_printf("%s: %s",
				reply.text_full, conn->disconnect_reason);
			i_free_and_null(conn->disconnect_reason);
		}
		reply.text_without_resp = reply.text_full;
		if (!conn->reconnecting) {
			imapc_login_callback(conn, &reply);
			i_free(conn->ips);
			conn->ips_count = 0;
		}
		array_clear(&conn->aborted_cmd_tags);
		conn->idling = FALSE;
		conn->idle_plus_waiting = FALSE;
		conn->idle_stopping = FALSE;

		conn->select_waiting_reply = FALSE;
		conn->selecting_box = NULL;
		conn->selected_box = NULL;
		/* fall through */
	case IMAPC_CONNECTION_STATE_DONE:
		/* if we came from imapc_client_get_capabilities(), stop so
		   it can finish up and not just hang indefinitely. */
		if (conn->client->stop_on_state_finish && !conn->reconnecting)
			imapc_client_stop(conn->client);
		break;
	default:
		break;
	}
}

static void imapc_connection_lfiles_free(struct imapc_connection *conn)
{
	struct imapc_arg_file *lfile;

	array_foreach_modifiable(&conn->literal_files, lfile) {
		if (close(lfile->fd) < 0)
			i_error("imapc: close(literal file) failed: %m");
	}
	array_clear(&conn->literal_files);
}

static void
imapc_connection_literal_reset(struct imapc_connection_literal *literal)
{
	i_close_fd_path(&literal->fd, literal->temp_path);
	i_free_and_null(literal->temp_path);

	i_zero(literal);
	literal->fd = -1;
}

void imapc_connection_disconnect_full(struct imapc_connection *conn,
				      bool reconnecting)
{
	/* timeout may be set also in disconnected state */
	timeout_remove(&conn->to);
	conn->reconnecting = reconnecting;

	if (conn->state == IMAPC_CONNECTION_STATE_DISCONNECTED)
		return;

	if (conn->client->set.debug)
		i_debug("imapc(%s): Disconnected", conn->name);

	if (conn->dns_lookup != NULL)
		dns_lookup_abort(&conn->dns_lookup);
	imapc_connection_lfiles_free(conn);
	imapc_connection_literal_reset(&conn->literal);
	timeout_remove(&conn->to_output);
	timeout_remove(&conn->to_throttle);
	timeout_remove(&conn->to_throttle_shrink);
	if (conn->parser != NULL)
		imap_parser_unref(&conn->parser);
	io_remove(&conn->io);
	ssl_iostream_destroy(&conn->ssl_iostream);
	if (conn->fd != -1) {
		i_stream_destroy(&conn->input);
		o_stream_destroy(&conn->output);
		net_disconnect(conn->fd);
		conn->fd = -1;
	}

	/* get capabilities again after reconnection. this is especially
	   important because post-login capabilities often do not contain AUTH=
	   capabilities. */
	conn->capabilities = 0;
	if (conn->capabilities_list != NULL) {
		p_strsplit_free(default_pool, conn->capabilities_list);
		conn->capabilities_list = NULL;
	}

	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DISCONNECTED);
	imapc_connection_abort_commands(conn, NULL, reconnecting);

	if (!reconnecting) {
		imapc_client_try_stop(conn->client);
	}
}

void imapc_connection_set_no_reconnect(struct imapc_connection *conn)
{
	conn->reconnect_ok = FALSE;
}

void imapc_connection_disconnect(struct imapc_connection *conn)
{
	imapc_connection_disconnect_full(conn, FALSE);
}

static void imapc_connection_set_disconnected(struct imapc_connection *conn)
{
	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DISCONNECTED);
	imapc_connection_abort_commands(conn, NULL, FALSE);
}

static bool imapc_connection_can_reconnect(struct imapc_connection *conn)
{
	if (conn->client->logging_out)
		return FALSE;
	if (conn->client->set.connect_retry_count == 0 ||
	    (conn->client->set.connect_retry_count < UINT_MAX &&
	     conn->reconnect_count >= conn->client->set.connect_retry_count))
		return FALSE;

	if (conn->selected_box != NULL)
		return imapc_client_mailbox_can_reconnect(conn->selected_box);
	else {
		return conn->reconnect_command_count == 0 &&
			conn->reconnect_ok;
	}
}

static void imapc_connection_reconnect(struct imapc_connection *conn)
{
	conn->reconnect_ok = FALSE;
	conn->reconnect_waiting = FALSE;

	if (conn->selected_box != NULL) {
		i_assert(!conn->selected_box->reconnecting);
		conn->selected_box->reconnecting = TRUE;
		/* if we fail again, avoid reconnecting immediately. if the
		   server is broken we could just get into an infinitely
		   failing reconnection loop. */
		conn->selected_box->reconnect_ok = FALSE;
	}
	imapc_connection_disconnect_full(conn, TRUE);
	imapc_connection_connect(conn);
}

void imapc_connection_try_reconnect(struct imapc_connection *conn,
				    const char *errstr,
				    unsigned int delay_msecs,
				    bool connect_error)
{
	/* Try the next IP address only for connect() problems. */
	if (conn->prev_connect_idx + 1 < conn->ips_count && connect_error) {
		i_warning("imapc(%s): %s - trying the next IP", conn->name, errstr);
		conn->reconnect_ok = TRUE;
		imapc_connection_disconnect_full(conn, TRUE);
		imapc_connection_connect(conn);
		return;
	}

	if (!imapc_connection_can_reconnect(conn)) {
		i_error("imapc(%s): %s - disconnecting", conn->name, errstr);
		imapc_connection_disconnect(conn);
	} else {
		conn->reconnecting = TRUE;
		i_warning("imapc(%s): %s - reconnecting (delay %u ms)", conn->name, errstr, delay_msecs);
		if (delay_msecs == 0)
			imapc_connection_reconnect(conn);
		else {
			imapc_connection_disconnect_full(conn, TRUE);
			conn->to = timeout_add(delay_msecs, imapc_connection_reconnect, conn);
			conn->reconnect_count++;
			conn->reconnect_waiting = TRUE;
		}
	}
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

static bool last_arg_is_fetch_body(const struct imap_arg *args,
				   const struct imap_arg **parent_arg_r,
				   unsigned int *idx_r)
{
	const struct imap_arg *list;
	const char *name;
	unsigned int count;

	if (args[0].type == IMAP_ARG_ATOM &&
	    imap_arg_atom_equals(&args[1], "FETCH") &&
	    imap_arg_get_list_full(&args[2], &list, &count) && count >= 2 &&
	    list[count].type == IMAP_ARG_LITERAL_SIZE &&
	    imap_arg_get_atom(&list[count-1], &name) &&
	    strncasecmp(name, "BODY[", 5) == 0) {
		*parent_arg_r = &args[2];
		*idx_r = count;
		return TRUE;
	}
	return FALSE;
}

static int
imapc_connection_read_literal_init(struct imapc_connection *conn, uoff_t size,
				   const struct imap_arg *args)
{
	const char *path;
	const struct imap_arg *parent_arg;
	unsigned int idx;

	i_assert(conn->literal.fd == -1);

	if (size <= IMAPC_MAX_INLINE_LITERAL_SIZE ||
	    !last_arg_is_fetch_body(args, &parent_arg, &idx)) {
		/* read the literal directly into parser */
		return 0;
	}

	conn->literal.fd = imapc_client_create_temp_fd(conn->client, &path);
	if (conn->literal.fd == -1)
		return -1;
	conn->literal.temp_path = i_strdup(path);
	conn->literal.bytes_left = size;
	conn->literal.parent_arg = parent_arg;
	conn->literal.list_idx = idx;
	return 1;
}

static int imapc_connection_read_literal(struct imapc_connection *conn)
{
	struct imapc_arg_file *lfile;
	const unsigned char *data;
	size_t size;

	if (conn->literal.bytes_left == 0)
		return 1;

	data = i_stream_get_data(conn->input, &size);
	if (size > conn->literal.bytes_left)
		size = conn->literal.bytes_left;
	if (size > 0) {
		if (write_full(conn->literal.fd, data, size) < 0) {
			i_error("imapc(%s): write(%s) failed: %m",
				conn->name, conn->literal.temp_path);
			imapc_connection_disconnect(conn);
			return -1;
		}
		i_stream_skip(conn->input, size);
		conn->literal.bytes_left -= size;
	}
	if (conn->literal.bytes_left > 0)
		return 0;

	/* finished */
	lfile = array_append_space(&conn->literal_files);
	lfile->fd = conn->literal.fd;
	lfile->parent_arg = conn->literal.parent_arg;
	lfile->list_idx = conn->literal.list_idx;

	conn->literal.fd = -1;
	imapc_connection_literal_reset(&conn->literal);
	return 1;
}

static int
imapc_connection_read_line_more(struct imapc_connection *conn,
				const struct imap_arg **imap_args_r)
{
	uoff_t literal_size;
	int ret;

	if ((ret = imapc_connection_read_literal(conn)) <= 0)
		return ret;

	ret = imap_parser_read_args(conn->parser, 0,
				    IMAP_PARSE_FLAG_LITERAL_SIZE |
				    IMAP_PARSE_FLAG_ATOM_ALLCHARS |
				    IMAP_PARSE_FLAG_LITERAL8 |
				    IMAP_PARSE_FLAG_SERVER_TEXT, imap_args_r);
	if (ret == -2) {
		/* need more data */
		return 0;
	}
	if (ret < 0) {
		enum imap_parser_error parser_error;
		const char *err_msg = imap_parser_get_error(conn->parser, &parser_error);
		if (parser_error != IMAP_PARSE_ERROR_BAD_SYNTAX)
			imapc_connection_input_error(conn, "Error parsing input: %s", err_msg);
		else
			i_error("Error parsing input: %s", err_msg);
		return -1;
	}

	if (imap_parser_get_literal_size(conn->parser, &literal_size)) {
		if (imapc_connection_read_literal_init(conn, literal_size,
						       *imap_args_r) <= 0) {
			imap_parser_read_last_literal(conn->parser);
			return 2;
		}
		return imapc_connection_read_line_more(conn, imap_args_r);
	}
	return 1;
}

static int
imapc_connection_read_line(struct imapc_connection *conn,
			   const struct imap_arg **imap_args_r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = imapc_connection_read_line_more(conn, imap_args_r)) == 2)
		;

	if (ret > 0) {
		data = i_stream_get_data(conn->input, &size);
		if (size >= 2 && data[0] == '\r' && data[1] == '\n')
			i_stream_skip(conn->input, 2);
		else if (size >= 1 && data[0] == '\n')
			i_stream_skip(conn->input, 1);
		else
			i_panic("imapc: Missing LF from input line");
	} else if (ret < 0) {
		data = i_stream_get_data(conn->input, &size);
		unsigned char *lf = memchr(data, '\n', size);
		if (lf != NULL)
			i_stream_skip(conn->input, (lf - data) + 1);
	}
	return ret;
}

static int
imapc_connection_parse_capability(struct imapc_connection *conn,
				  const char *value)
{
	const char *const *tmp;
	unsigned int i;

	if (conn->client->set.debug) {
		i_debug("imapc(%s): Server capabilities: %s",
			conn->name, value);
	}

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
		*value_r = "";
	}
	return imapc_connection_handle_resp_text_code(conn, *key_r, *value_r);
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
	return imapc_connection_handle_resp_text(conn, text, key_r, value_r);
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
	if (conn->parser != NULL)
		imap_parser_reset(conn->parser);
	imapc_connection_lfiles_free(conn);
}

static void
imapc_connection_auth_finish(struct imapc_connection *conn,
			     const struct imapc_command_reply *reply)
{
	if (reply->state != IMAPC_COMMAND_STATE_OK) {
		imapc_auth_failed(conn, reply, reply->text_full);
		imapc_connection_disconnect(conn);
		return;
	}

	imapc_auth_ok(conn);

	timeout_remove(&conn->to);
	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_DONE);
	imapc_login_callback(conn, reply);

	imapc_command_send_more(conn);
}

static void imapc_connection_login_cb(const struct imapc_command_reply *reply,
				      void *context)
{
	struct imapc_connection *conn = context;

	imapc_connection_auth_finish(conn, reply);
}

static void
imapc_connection_proxyauth_login_cb(const struct imapc_command_reply *reply,
				    void *context)
{
	struct imapc_connection *conn = context;
	const struct imapc_client_settings *set = &conn->client->set;
	struct imapc_command *cmd;

	if (reply->state == IMAPC_COMMAND_STATE_OK) {
		cmd = imapc_connection_cmd(conn, imapc_connection_login_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_sendf(cmd, "PROXYAUTH %s", set->username);
		imapc_command_send_more(conn);
	} else {
		imapc_connection_auth_finish(conn, reply);
	}
}

static void
imapc_connection_authenticate_cb(const struct imapc_command_reply *reply,
				 void *context)
{
	struct imapc_connection *conn = context;
	const unsigned char *sasl_output;
	size_t input_len, sasl_output_len;
	buffer_t *buf;
	const char *error;

	if ((int)reply->state != IMAPC_COMMAND_STATE_AUTHENTICATE_CONTINUE) {
		dsasl_client_free(&conn->sasl_client);
		imapc_connection_auth_finish(conn, reply);
		return;
	}

	input_len = strlen(reply->text_full);
	buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(input_len));
	if (base64_decode(reply->text_full, input_len, NULL, buf) < 0) {
		imapc_auth_failed(conn, reply,
				  t_strdup_printf("Server sent non-base64 input for AUTHENTICATE: %s",
						  reply->text_full));
	} else if (dsasl_client_input(conn->sasl_client, buf->data, buf->used, &error) < 0) {
		imapc_auth_failed(conn, reply, error);
	} else if (dsasl_client_output(conn->sasl_client, &sasl_output,
				       &sasl_output_len, &error) < 0) {
		imapc_auth_failed(conn, reply, error);
	} else {
		string_t *imap_output =
			t_str_new(MAX_BASE64_ENCODED_SIZE(sasl_output_len)+2);
		base64_encode(sasl_output, sasl_output_len, imap_output);
		str_append(imap_output, "\r\n");
		o_stream_nsend(conn->output, str_data(imap_output),
			       str_len(imap_output));
		return;
	}
	imapc_connection_disconnect(conn);
}

static bool imapc_connection_have_auth(struct imapc_connection *conn,
				       const char *mech_name)
{
	char *const *capa;

	for (capa = conn->capabilities_list; *capa != NULL; capa++) {
		if (strncasecmp(*capa, "AUTH=", 5) == 0 &&
		    strcasecmp((*capa)+5, mech_name) == 0)
			return TRUE;
	}
	return FALSE;
}

static int
imapc_connection_get_sasl_mech(struct imapc_connection *conn,
			       const struct dsasl_client_mech **mech_r,
			       const char **error_r)
{
	const struct imapc_client_settings *set = &conn->client->set;
	const char *const *mechanisms =
		t_strsplit_spaces(set->sasl_mechanisms, ", ");

	/* find one of the specified SASL mechanisms */
	for (; *mechanisms != NULL; mechanisms++) {
		if (imapc_connection_have_auth(conn, *mechanisms)) {
			*mech_r = dsasl_client_mech_find(*mechanisms);
			if (*mech_r != NULL)
				return 0;

			*error_r = t_strdup_printf(
				"Support for SASL method '%s' is missing", *mechanisms);
			return -1;
		}
	}
	*error_r = t_strdup_printf("IMAP server doesn't support any of the requested SASL mechanisms: %s",
				   set->sasl_mechanisms);
	return -1;
}

static void imapc_connection_authenticate(struct imapc_connection *conn)
{
	const struct imapc_client_settings *set = &conn->client->set;
	struct imapc_command *cmd;
	struct dsasl_client_settings sasl_set;
	const struct dsasl_client_mech *sasl_mech = NULL;
	const char *error;

	if (conn->client->set.debug) {
		if (set->master_user == NULL) {
			i_debug("imapc(%s): Authenticating as %s",
				conn->name, set->username);
		} else {
			i_debug("imapc(%s): Authenticating as %s for user %s",
				conn->name, set->master_user, set->username);
		}
	}

	if (set->sasl_mechanisms != NULL && set->sasl_mechanisms[0] != '\0') {
		if (imapc_connection_get_sasl_mech(conn, &sasl_mech, &error) < 0) {
			struct imapc_command_reply reply;
			i_zero(&reply);
			reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;
			reply.text_full = "";
			imapc_auth_failed(conn, &reply, error);
			imapc_connection_disconnect(conn);
			return;
		}
	}

	if (set->use_proxyauth && set->master_user != NULL) {
		/* We can use LOGIN command */
		cmd = imapc_connection_cmd(conn, imapc_connection_proxyauth_login_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_sendf(cmd, "LOGIN %s %s",
				    set->master_user, set->password);
		return;
	}
	if (sasl_mech == NULL &&
	    ((set->master_user == NULL &&
	      !need_literal(set->username) && !need_literal(set->password)) ||
	     (conn->capabilities & IMAPC_CAPABILITY_AUTH_PLAIN) == 0)) {
		/* We can use LOGIN command */
		cmd = imapc_connection_cmd(conn, imapc_connection_login_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_sendf(cmd, "LOGIN %s %s",
				    set->username, set->password);
		return;
	}

	i_zero(&sasl_set);
	if (set->master_user == NULL)
		sasl_set.authid = set->username;
	else {
		sasl_set.authid = set->master_user;
		sasl_set.authzid = set->username;
	}
	sasl_set.password = set->password;

	if (sasl_mech == NULL)
		sasl_mech = &dsasl_client_mech_plain;
	conn->sasl_client = dsasl_client_new(sasl_mech, &sasl_set);

	cmd = imapc_connection_cmd(conn, imapc_connection_authenticate_cb, conn);
	cmd->authenticate = TRUE;
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);

	if ((conn->capabilities & IMAPC_CAPABILITY_SASL_IR) != 0) {
		const unsigned char *sasl_output;
		size_t sasl_output_len;
		string_t *sasl_output_base64;
		const char *error;

		if (dsasl_client_output(conn->sasl_client, &sasl_output,
					&sasl_output_len, &error) < 0) {
			i_error("imapc(%s): Failed to create initial SASL reply: %s",
				conn->name, error);
			imapc_connection_disconnect(conn);
			return;
		}
		sasl_output_base64 = t_str_new(MAX_BASE64_ENCODED_SIZE(sasl_output_len));
		base64_encode(sasl_output, sasl_output_len, sasl_output_base64);

		imapc_command_sendf(cmd, "AUTHENTICATE %1s %1s",
				    dsasl_client_mech_get_name(sasl_mech),
				    str_c(sasl_output_base64));
	} else {
		imapc_command_sendf(cmd, "AUTHENTICATE %1s",
				    dsasl_client_mech_get_name(sasl_mech));
	}
}

static void
imapc_connection_starttls_cb(const struct imapc_command_reply *reply,
			     void *context)
{
	struct imapc_connection *conn = context;
	struct imapc_command *cmd;

	if (reply->state != IMAPC_COMMAND_STATE_OK) {
		imapc_connection_input_error(conn, "STARTTLS failed: %s",
					     reply->text_full);
		return;
	}

	if (imapc_connection_ssl_init(conn) < 0)
		imapc_connection_disconnect(conn);
	else {
		/* get updated capabilities */
		cmd = imapc_connection_cmd(conn, imapc_connection_capability_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_send(cmd, "CAPABILITY");
	}
}

static void
imapc_connection_id_callback(const struct imapc_command_reply *reply ATTR_UNUSED,
			     void *context ATTR_UNUSED)
{
}

static void imapc_connection_send_id(struct imapc_connection *conn)
{
	static unsigned int global_id_counter = 0;
	struct imapc_command *cmd;

	if ((conn->capabilities & IMAPC_CAPABILITY_ID) == 0 ||
	    conn->client->set.session_id_prefix == NULL)
		return;

	cmd = imapc_connection_cmd(conn, imapc_connection_id_callback, conn);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
	imapc_command_send(cmd, t_strdup_printf(
		"ID (\"name\" \"Dovecot\" \"x-session-ext-id\" \"%s-%u\")",
		conn->client->set.session_id_prefix, ++global_id_counter));
}

static void imapc_connection_starttls(struct imapc_connection *conn)
{
	struct imapc_command *cmd;

	if (conn->client->set.ssl_mode == IMAPC_CLIENT_SSL_MODE_STARTTLS &&
	    conn->ssl_iostream == NULL) {
		if ((conn->capabilities & IMAPC_CAPABILITY_STARTTLS) == 0) {
			i_error("imapc(%s): Requested STARTTLS, "
				"but server doesn't support it",
				conn->name);
			imapc_connection_disconnect(conn);
			return;
		}
		cmd = imapc_connection_cmd(conn, imapc_connection_starttls_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_send(cmd, "STARTTLS");
		return;
	}
	imapc_connection_send_id(conn);
	imapc_connection_authenticate(conn);
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
		imapc_connection_starttls(conn);
	}
}

static int imapc_connection_input_banner(struct imapc_connection *conn)
{
	const struct imap_arg *imap_args;
	const char *key, *value;
	struct imapc_command *cmd;
	int ret;

	if ((ret = imapc_connection_read_line(conn, &imap_args)) <= 0)
		return ret;
	/* we already verified that the banner beigns with OK */
	i_assert(imap_arg_atom_equals(imap_args, "OK"));
	imap_args++;

	if (imapc_connection_handle_imap_resp_text(conn, imap_args,
						   &key, &value) < 0)
		return -1;
	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_AUTHENTICATING);

	if (conn->capabilities == 0) {
		/* capabilities weren't sent in the banner. ask for them. */
		cmd = imapc_connection_cmd(conn, imapc_connection_capability_cb,
					   conn);
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_PRELOGIN);
		imapc_command_send(cmd, "CAPABILITY");
	} else {
		imapc_connection_starttls(conn);
	}
	conn->input_callback = NULL;
	imapc_connection_input_reset(conn);
	return 1;
}

static int imapc_connection_input_untagged(struct imapc_connection *conn)
{
	const struct imap_arg *imap_args;
	const unsigned char *data;
	size_t size;
	const char *name, *value;
	struct imap_parser *parser;
	struct imapc_untagged_reply reply;
	int ret;

	if (conn->state == IMAPC_CONNECTION_STATE_CONNECTING) {
		/* input banner */
		data = i_stream_get_data(conn->input, &size);
		if (size < 3 && memchr(data, '\n', size) == NULL)
			return 0;
		if (i_memcasecmp(data, "OK ", 3) != 0) {
			imapc_connection_input_error(conn,
				"Banner doesn't begin with OK: %s",
				t_strcut(t_strndup(data, size), '\n'));
			return -1;
		}
		conn->input_callback = imapc_connection_input_banner;
		return 1;
	}

	if ((ret = imapc_connection_read_line(conn, &imap_args)) == 0)
		return 0;
	else if (ret < 0) {
		imapc_connection_input_reset(conn);
		return 1;
	}
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
	i_zero(&reply);

	if (strcasecmp(name, "OK") == 0) {
		if (imapc_connection_handle_imap_resp_text(conn, imap_args,
						&reply.resp_text_key,
						&reply.resp_text_value) < 0)
			return -1;
	} else if (strcasecmp(name, "CAPABILITY") == 0) {
		value = imap_args_to_str(imap_args);
		if (imapc_connection_parse_capability(conn, value) < 0)
			return -1;
	} else if (strcasecmp(name, "BYE") == 0) {
		i_free(conn->disconnect_reason);
		conn->disconnect_reason = i_strdup(imap_args_to_str(imap_args));
	}

	reply.name = name;
	reply.num = conn->cur_num;
	reply.args = imap_args;
	reply.file_args = array_get(&conn->literal_files,
				    &reply.file_args_count);

	if (conn->selected_box != NULL) {
		reply.untagged_box_context =
			conn->selected_box->untagged_box_context;
	}

	/* the callback may disconnect and destroy the parser */
	parser = conn->parser;
	imap_parser_ref(parser);
	conn->client->untagged_callback(&reply, conn->client->untagged_context);
	imap_parser_unref(&parser);
	imapc_connection_input_reset(conn);
	return 1;
}

static int imapc_connection_input_plus(struct imapc_connection *conn)
{
	struct imapc_command *const *cmds;
	unsigned int cmds_count;
	const char *line;

	if ((line = i_stream_next_line(conn->input)) == NULL)
		return 0;

	cmds = array_get(&conn->cmd_send_queue, &cmds_count);
	if (conn->idle_plus_waiting) {
		/* "+ idling" reply for IDLE command */
		conn->idle_plus_waiting = FALSE;
		conn->idling = TRUE;
		/* no timing out while IDLEing */
		if (conn->to != NULL && !conn->idle_stopping)
			timeout_remove(&conn->to);
	} else if (cmds_count > 0 && cmds[0]->wait_for_literal) {
		/* reply for literal */
		cmds[0]->wait_for_literal = FALSE;
		imapc_command_send_more(conn);
	} else {
		cmds = array_get(&conn->cmd_wait_list, &cmds_count);
		if (cmds_count > 0 && cmds[0]->authenticate) {
			/* continue AUTHENTICATE */
			struct imapc_command_reply reply;

			i_zero(&reply);
			reply.state = (enum imapc_command_state)IMAPC_COMMAND_STATE_AUTHENTICATE_CONTINUE;
			reply.text_full = line;
			cmds[0]->callback(&reply, cmds[0]->context);
		} else {
			imapc_connection_input_error(conn, "Unexpected '+': %s", line);
			return -1;
		}
	}

	imapc_connection_input_reset(conn);
	return 1;
}

static void
imapc_connection_throttle_shrink_timeout(struct imapc_connection *conn)
{
	if (conn->throttle_msecs <= 1)
		conn->throttle_msecs = 0;
	else
		conn->throttle_msecs = conn->throttle_msecs*3 / 4;

	if (conn->throttle_shrink_msecs <= conn->client->set.throttle_set.shrink_min_msecs)
		conn->throttle_shrink_msecs = 0;
	else
		conn->throttle_shrink_msecs = conn->throttle_shrink_msecs*3 / 4;

	timeout_remove(&conn->to_throttle_shrink);
	if (conn->throttle_shrink_msecs > 0) {
		conn->to_throttle_shrink =
			timeout_add(conn->throttle_shrink_msecs,
				    imapc_connection_throttle_shrink_timeout, conn);
	}
}

static void
imapc_connection_throttle(struct imapc_connection *conn,
			  const struct imapc_command_reply *reply)
{
	timeout_remove(&conn->to_throttle);

	/* If GMail returns [THROTTLED], start slowing down commands.
	   Unfortunately this isn't a nice resp-text-code, but just
	   appended at the end of the line (although we kind of support
	   it as resp-text-code also in here if it's uppercased). */
	if (strstr(reply->text_full, "[THROTTLED]") != NULL) {
		if (conn->throttle_msecs == 0)
			conn->throttle_msecs = conn->client->set.throttle_set.init_msecs;
		else if (conn->throttle_msecs < conn->last_successful_throttle_msecs)
			conn->throttle_msecs = conn->last_successful_throttle_msecs;
		else {
			conn->throttle_msecs *= 2;
			if (conn->throttle_msecs > conn->client->set.throttle_set.max_msecs)
				conn->throttle_msecs = conn->client->set.throttle_set.max_msecs;
		}
		if (conn->throttle_shrink_msecs == 0)
			conn->throttle_shrink_msecs = conn->client->set.throttle_set.shrink_min_msecs;
		else
			conn->throttle_shrink_msecs *= 2;
		if (conn->to_throttle_shrink != NULL)
			timeout_reset(conn->to_throttle_shrink);
	} else {
		if (conn->throttle_shrink_msecs > 0 &&
		    conn->to_throttle_shrink == NULL) {
			conn->to_throttle_shrink =
				timeout_add(conn->throttle_shrink_msecs,
					    imapc_connection_throttle_shrink_timeout, conn);
		}
		conn->last_successful_throttle_msecs = conn->throttle_msecs;
	}

	if (conn->throttle_msecs > 0) {
		conn->throttle_end_timeval = ioloop_timeval;
		timeval_add_msecs(&conn->throttle_end_timeval,
				  conn->throttle_msecs);
		conn->throttle_pending = TRUE;
	}
}

static void
imapc_command_reply_free(struct imapc_command *cmd,
			 const struct imapc_command_reply *reply)
{
	cmd->callback(reply, cmd->context);
	imapc_command_free(cmd);
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
	/* make sure reply texts stays valid if input stream gets freed */
	line = t_strdup_noconst(line);

	i_zero(&reply);

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
	else if (strcasecmp(line, "bad") == 0)
		reply.state = IMAPC_COMMAND_STATE_BAD;
	else {
		imapc_connection_input_error(conn,
			"Invalid state in tagged reply: %u %s %s",
			conn->cur_tag, line, reply.text_full);
		return -1;
	}

	if (reply.text_full[0] == '[') {
		/* get resp-text */
		if (imapc_connection_handle_resp_text(conn, reply.text_full,
					&reply.resp_text_key,
					&reply.resp_text_value) < 0)
			return -1;

		p = i_strchr_to_next(reply.text_full, ']');
		i_assert(p != NULL);
		reply.text_without_resp = p;
		if (reply.text_without_resp[0] == ' ')
			reply.text_without_resp++;
	} else {
		reply.text_without_resp = reply.text_full;
	}
	/* if we've pipelined multiple commands, handle [THROTTLED] reply
	   from only one of them */
	if (!conn->throttle_pending)
		imapc_connection_throttle(conn, &reply);

	/* find the command. it's either the first command in send queue
	   (literal failed) or somewhere in wait list. */
	cmds = array_get(&conn->cmd_send_queue, &count);
	if (count > 0 && cmds[0]->tag == conn->cur_tag) {
		cmd = cmds[0];
		array_pop_front(&conn->cmd_send_queue);
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
	if (array_count(&conn->cmd_wait_list) == 0 &&
	    array_count(&conn->cmd_send_queue) == 0 &&
	    conn->state == IMAPC_CONNECTION_STATE_DONE && conn->to != NULL)
		timeout_remove(&conn->to);

	if (cmd == NULL) {
		if (seq_range_exists(&conn->aborted_cmd_tags, conn->cur_tag)) {
			/* sent command was already aborted - ignore it */
			seq_range_array_remove(&conn->aborted_cmd_tags,
					       conn->cur_tag);
			imapc_connection_input_reset(conn);
			return 1;
		}
		imapc_connection_input_error(conn,
			"Unknown tag in a reply: %u %s %s",
			conn->cur_tag, line, reply.text_full);
		return -1;
	}
	if ((cmd->flags & IMAPC_COMMAND_FLAG_SELECT) != 0)
		conn->select_waiting_reply = FALSE;

	if (reply.state == IMAPC_COMMAND_STATE_BAD) {
		i_error("imapc(%s): Command '%s' failed with BAD: %u %s",
			conn->name, imapc_command_get_readable(cmd),
			conn->cur_tag, reply.text_full);
		imapc_connection_disconnect(conn);
	}

	if (reply.state == IMAPC_COMMAND_STATE_NO &&
	    (cmd->flags & IMAPC_COMMAND_FLAG_SELECT) != 0 &&
	    conn->selected_box != NULL) {
		/* EXAMINE/SELECT failed: mailbox is no longer selected */
		imapc_connection_unselect(conn->selected_box);
	}

	if (conn->reconnect_command_count > 0 &&
	    (cmd->flags & IMAPC_COMMAND_FLAG_RECONNECTED) != 0) {
		i_assert(conn->reconnect_command_count > 0);
		if (--conn->reconnect_command_count == 0) {
			/* we've received replies for all the commands started
			   before reconnection. if we get disconnected now, we
			   can safely reconnect without worrying about infinite
			   reconnect loops. */
			if (conn->selected_box != NULL)
				conn->selected_box->reconnect_ok = TRUE;
		}
	}
	if (conn->reconnect_command_count == 0) {
		/* we've successfully received replies to some commands. */
		conn->reconnect_ok = TRUE;
	}
	imapc_connection_input_reset(conn);
	imapc_command_reply_free(cmd, &reply);
	imapc_command_send_more(conn);
	return 1;
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

		if (strcmp(tag, "*") == 0) {
			conn->input_state = IMAPC_INPUT_STATE_UNTAGGED;
			conn->cur_num = 0;
			ret = imapc_connection_input_untagged(conn);
		} else if (strcmp(tag, "+") == 0) {
			conn->input_state = IMAPC_INPUT_STATE_PLUS;
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
	case IMAPC_INPUT_STATE_PLUS:
		ret = imapc_connection_input_plus(conn);
		break;
	case IMAPC_INPUT_STATE_UNTAGGED:
	case IMAPC_INPUT_STATE_UNTAGGED_NUM:
		ret = imapc_connection_input_untagged(conn);
		break;
	case IMAPC_INPUT_STATE_TAGGED:
		ret = imapc_connection_input_tagged(conn);
		break;
	}
	return ret;
}

static void imapc_connection_input(struct imapc_connection *conn)
{
	const char *errstr;
	string_t *str;
	ssize_t ret = 0;

	/* we need to read as much as we can with SSL streams to avoid
	   hanging */
	imapc_connection_ref(conn);
	while (conn->input != NULL && (ret = i_stream_read(conn->input)) > 0)
		imapc_connection_input_pending(conn);

	if (ret < 0 && conn->client->logging_out &&
	    conn->disconnect_reason != NULL) {
		/* expected disconnection */
	} else if (ret < 0) {
		/* disconnected or buffer full */
		str = t_str_new(128);
		if (conn->disconnect_reason != NULL) {
			str_printfa(str, "Server disconnected with message: %s",
				    conn->disconnect_reason);
		} else if (ret == -2) {
			str_printfa(str, "Server sent too large input "
				    "(buffer full at %"PRIuSIZE_T")",
				    i_stream_get_data_size(conn->input));
		} else if (conn->ssl_iostream == NULL) {
			errstr = conn->input->stream_errno == 0 ? "EOF" :
				i_stream_get_error(conn->input);
			str_printfa(str, "Server disconnected unexpectedly: %s",
				    errstr);
		} else {
			errstr = ssl_iostream_get_last_error(conn->ssl_iostream);
			if (errstr == NULL) {
				errstr = conn->input->stream_errno == 0 ? "EOF" :
					i_stream_get_error(conn->input);
			}
			str_printfa(str, "Server disconnected unexpectedly: %s",
				    errstr);
		}
		imapc_connection_try_reconnect(conn, str_c(str), 0, FALSE);
	}
	imapc_connection_unref(&conn);
}

static int imapc_connection_ssl_handshaked(const char **error_r, void *context)
{
	struct imapc_connection *conn = context;
	const char *error;

	if (ssl_iostream_check_cert_validity(conn->ssl_iostream,
					     conn->client->set.host, &error) == 0) {
		if (conn->client->set.debug) {
			i_debug("imapc(%s): SSL handshake successful",
				conn->name);
		}
		return 0;
	} else if (conn->client->set.ssl_set.allow_invalid_cert) {
		if (conn->client->set.debug) {
			i_debug("imapc(%s): SSL handshake successful, "
				"ignoring invalid certificate: %s",
				conn->name, error);
		}
		return 0;
	} else {
		*error_r = error;
		return -1;
	}
}

static int imapc_connection_ssl_init(struct imapc_connection *conn)
{
	const char *error;

	if (conn->client->ssl_ctx == NULL) {
		i_error("imapc(%s): No SSL context", conn->name);
		return -1;
	}

	if (conn->client->set.debug)
		i_debug("imapc(%s): Starting SSL handshake", conn->name);

	if (conn->raw_input != conn->input) {
		/* recreate rawlog after STARTTLS */
		i_stream_ref(conn->raw_input);
		o_stream_ref(conn->raw_output);
		i_stream_destroy(&conn->input);
		o_stream_destroy(&conn->output);
		conn->input = conn->raw_input;
		conn->output = conn->raw_output;
	}

	io_remove(&conn->io);
	if (io_stream_create_ssl_client(conn->client->ssl_ctx,
					conn->client->set.host,
					&conn->client->set.ssl_set,
					&conn->input, &conn->output,
					&conn->ssl_iostream, &error) < 0) {
		i_error("imapc(%s): Couldn't initialize SSL client: %s",
			conn->name, error);
		return -1;
	}
	conn->io = io_add_istream(conn->input, imapc_connection_input, conn);
	ssl_iostream_set_handshake_callback(conn->ssl_iostream,
					    imapc_connection_ssl_handshaked,
					    conn);
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		i_error("imapc(%s): SSL handshake failed: %s", conn->name,
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	if (*conn->client->set.rawlog_dir != '\0') {
		iostream_rawlog_create(conn->client->set.rawlog_dir,
				       &conn->input, &conn->output);
	}

	imap_parser_set_streams(conn->parser, conn->input, NULL);
	return 0;
}

static int imapc_connection_connected(struct imapc_connection *conn)
{
	const struct ip_addr *ip = &conn->ips[conn->prev_connect_idx];
	struct ip_addr local_ip;
	in_port_t local_port;
	int err;

	i_assert(conn->io == NULL);

	err = net_geterror(conn->fd);
	if (err != 0) {
		imapc_connection_try_reconnect(conn, t_strdup_printf(
			"connect(%s, %u) failed: %s",
			net_ip2addr(ip), conn->client->set.port,
			strerror(err)), conn->client->set.connect_retry_interval_msecs, TRUE);
		return -1;
	}
	if (net_getsockname(conn->fd, &local_ip, &local_port) < 0)
		local_port = 0;
	i_info("imapc(%s): Connected to %s:%u (local %s:%u)", conn->name,
	       net_ip2addr(ip), conn->client->set.port,
	       net_ip2addr(&local_ip), local_port);
	conn->io = io_add(conn->fd, IO_READ, imapc_connection_input, conn);
	o_stream_set_flush_callback(conn->output, imapc_connection_output,
				    conn);

	if (conn->client->set.ssl_mode == IMAPC_CLIENT_SSL_MODE_IMMEDIATE) {
		if (imapc_connection_ssl_init(conn) < 0)
			imapc_connection_disconnect(conn);
	}
	return imapc_connection_output(conn);
}

static void imapc_connection_timeout(struct imapc_connection *conn)
{
	const struct ip_addr *ip = &conn->ips[conn->prev_connect_idx];
	const char *errstr;
	bool connect_error = FALSE;

	switch (conn->state) {
	case IMAPC_CONNECTION_STATE_CONNECTING:
		errstr = t_strdup_printf("connect(%s, %u) timed out after %u seconds",
			net_ip2addr(ip), conn->client->set.port,
			conn->client->set.connect_timeout_msecs/1000);
		connect_error = TRUE;
		break;
	case IMAPC_CONNECTION_STATE_AUTHENTICATING:
		errstr = t_strdup_printf("Authentication timed out after %u seconds",
			conn->client->set.connect_timeout_msecs/1000);
		break;
	default:
		i_unreached();
	}
	imapc_connection_try_reconnect(conn, errstr, 0, connect_error);
}

static void
imapc_noop_callback(const struct imapc_command_reply *reply ATTR_UNUSED,
		    void *context ATTR_UNUSED)
{
}

static void
imapc_reidle_callback(const struct imapc_command_reply *reply ATTR_UNUSED,
		      void *context)
{
	struct imapc_connection *conn = context;

	imapc_connection_idle(conn);
}

static void imapc_connection_reset_idle(struct imapc_connection *conn)
{
	struct imapc_command *cmd;

	if (conn->idling)
		cmd = imapc_connection_cmd(conn, imapc_reidle_callback, conn);
	else if (array_count(&conn->cmd_wait_list) == 0)
		cmd = imapc_connection_cmd(conn, imapc_noop_callback, NULL);
	else {
		/* IMAP command reply is taking a long time */
		return;
	}
	imapc_command_send(cmd, "NOOP");
}

static void imapc_connection_connect_next_ip(struct imapc_connection *conn)
{
	const struct ip_addr *ip = NULL;
	unsigned int i;
	int fd;

	i_assert(conn->client->set.max_idle_time > 0);

	for (i = 0; i<conn->ips_count;) {
		conn->prev_connect_idx = (conn->prev_connect_idx+1) % conn->ips_count;
		ip = &conn->ips[conn->prev_connect_idx];
		fd = net_connect_ip(ip, conn->client->set.port, NULL);
		if (fd != -1)
			break;

		/* failed to connect to one of the IPs immediately
		   (e.g. IPv6 address without connectivity). try all IPs
		   before failing completely. */
		i_error("net_connect_ip(%s:%u) failed: %m",
			net_ip2addr(ip), conn->client->set.port);
		if (conn->prev_connect_idx+1 == conn->ips_count) {
			imapc_connection_try_reconnect(conn, "No more IP address(es) to try",
				conn->client->set.connect_retry_interval_msecs, TRUE);
			return;
		}
	}

	i_assert(ip != NULL);

	conn->fd = fd;
	conn->input = conn->raw_input =
		i_stream_create_fd(fd, conn->client->set.max_line_length);
	conn->output = conn->raw_output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);

	if (*conn->client->set.rawlog_dir != '\0' &&
	    conn->client->set.ssl_mode != IMAPC_CLIENT_SSL_MODE_IMMEDIATE) {
		iostream_rawlog_create(conn->client->set.rawlog_dir,
				       &conn->input, &conn->output);
	}

	o_stream_set_flush_pending(conn->output, TRUE);
	o_stream_set_flush_callback(conn->output, imapc_connection_connected,
				    conn);
	conn->parser = imap_parser_create(conn->input, NULL,
					  conn->client->set.max_line_length);
	conn->to = timeout_add(conn->client->set.connect_timeout_msecs,
			       imapc_connection_timeout, conn);
	conn->to_output = timeout_add(conn->client->set.max_idle_time*1000,
				      imapc_connection_reset_idle, conn);
	if (conn->client->set.debug) {
		i_debug("imapc(%s): Connecting to %s:%u", conn->name,
			net_ip2addr(ip), conn->client->set.port);
	}
}

static void
imapc_connection_dns_callback(const struct dns_lookup_result *result,
			      struct imapc_connection *conn)
{
	conn->dns_lookup = NULL;

	if (result->ret != 0) {
		i_error("imapc(%s): dns_lookup(%s) failed: %s",
			conn->name, conn->client->set.host, result->error);
		imapc_connection_set_disconnected(conn);
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
	struct ip_addr ip, *ips;
	unsigned int ips_count;
	int ret;

	if (conn->fd != -1 || conn->dns_lookup != NULL)
		return;
	if (conn->reconnect_waiting) {
		/* wait for the reconnection delay to finish before
		   doing anything. */
		return;
	}

	conn->reconnecting = FALSE;
	/* if we get disconnected before we've finished all the pending
	   commands, don't reconnect */
	conn->reconnect_command_count = array_count(&conn->cmd_wait_list) +
		array_count(&conn->cmd_send_queue);

	imapc_connection_input_reset(conn);
	conn->last_connect = ioloop_timeval;

	if (conn->client->set.debug) {
		i_debug("imapc(%s): Looking up IP address "
			"(reconnect_ok=%s, last_connect=%ld)", conn->name,
			(conn->reconnect_ok ? "true" : "false"),
			(long)conn->last_connect.tv_sec);
	}

	i_zero(&dns_set);
	dns_set.dns_client_socket_path =
		conn->client->set.dns_client_socket_path;
	dns_set.timeout_msecs = conn->client->set.connect_timeout_msecs;

	imapc_connection_set_state(conn, IMAPC_CONNECTION_STATE_CONNECTING);
	if (conn->ips_count > 0) {
		/* do nothing */
	} else if (net_addr2ip(conn->client->set.host, &ip) == 0) {
		conn->ips_count = 1;
		conn->ips = i_new(struct ip_addr, conn->ips_count);
		conn->ips[0] = ip;
	} else if (*dns_set.dns_client_socket_path == '\0') {
		ret = net_gethostbyname(conn->client->set.host,
					&ips, &ips_count);
		if (ret != 0) {
			i_error("imapc(%s): net_gethostbyname(%s) failed: %s",
				conn->name, conn->client->set.host,
				net_gethosterror(ret));
			imapc_connection_set_disconnected(conn);
			return;
		}
		conn->ips_count = ips_count;
		conn->ips = i_new(struct ip_addr, ips_count);
		memcpy(conn->ips, ips, ips_count * sizeof(*ips));
	} else {
		(void)dns_lookup(conn->client->set.host, &dns_set,
				 imapc_connection_dns_callback, conn,
				 &conn->dns_lookup);
		return;
	}
	imapc_connection_connect_next_ip(conn);
}

void imapc_connection_input_pending(struct imapc_connection *conn)
{
	int ret = 1;

	if (conn->input == NULL)
		return;

	if (conn->to != NULL && !conn->idle_stopping)
		timeout_reset(conn->to);

	o_stream_cork(conn->output);
	while (ret > 0 && conn->input != NULL) {
		T_BEGIN {
			ret = imapc_connection_input_one(conn);
		} T_END;
	}

	if (conn->output != NULL)
		o_stream_uncork(conn->output);
}

static struct imapc_command *
imapc_command_begin(imapc_command_callback_t *callback, void *context)
{
	struct imapc_command *cmd;
	pool_t pool;

	i_assert(callback != NULL);

	pool = pool_alloconly_create("imapc command", 2048);
	cmd = p_new(pool, struct imapc_command, 1);
	cmd->pool = pool;
	cmd->callback = callback;
	cmd->context = context;

	/* use a globally unique tag counter so looking at rawlogs is
	   somewhat easier */
	if (++imapc_client_cmd_tag_counter == 0)
		imapc_client_cmd_tag_counter++;
	cmd->tag = imapc_client_cmd_tag_counter;
	return cmd;
}

static void imapc_command_free(struct imapc_command *cmd)
{
	struct imapc_command_stream *stream;

	if (array_is_created(&cmd->streams)) {
		array_foreach_modifiable(&cmd->streams, stream)
			i_stream_unref(&stream->input);
	}
	pool_unref(&cmd->pool);
}

const char *imapc_command_get_tag(struct imapc_command *cmd)
{
	return t_strdup_printf("%u", cmd->tag);
}

void imapc_command_abort(struct imapc_command **_cmd)
{
	struct imapc_command *cmd = *_cmd;

	*_cmd = NULL;
	imapc_command_free(cmd);
}

static void imapc_command_timeout(struct imapc_connection *conn)
{
	struct imapc_command *const *cmds;
	unsigned int count;

	cmds = array_get(&conn->cmd_wait_list, &count);
	i_assert(count > 0);

	imapc_connection_try_reconnect(conn, t_strdup_printf(
		"Command '%s' timed out", imapc_command_get_readable(cmds[0])), 0, FALSE);
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

static void imapc_command_send_finished(struct imapc_connection *conn,
					struct imapc_command *cmd)
{
	struct imapc_command *const *cmdp;

	if (cmd->idle)
		conn->idle_plus_waiting = TRUE;
	cmd->sent = TRUE;

	/* everything sent. move command to wait list. */
	cmdp = array_front(&conn->cmd_send_queue);
	i_assert(*cmdp == cmd);
	array_pop_front(&conn->cmd_send_queue);
	array_push_back(&conn->cmd_wait_list, &cmd);

	/* send the next command in queue */
	imapc_command_send_more(conn);
}

static struct imapc_command_stream *
imapc_command_get_sending_stream(struct imapc_command *cmd)
{
	struct imapc_command_stream *stream;

	if (!array_is_created(&cmd->streams) || array_count(&cmd->streams) == 0)
		return NULL;

	stream = array_front_modifiable(&cmd->streams);
	if (stream->pos != cmd->send_pos)
		return NULL;
	return stream;
}

static int imapc_command_try_send_stream(struct imapc_connection *conn,
					 struct imapc_command *cmd)
{
	struct imapc_command_stream *stream;
	enum ostream_send_istream_result res;

	stream = imapc_command_get_sending_stream(cmd);
	if (stream == NULL)
		return -2;

	/* we're sending the stream now */
	o_stream_set_max_buffer_size(conn->output, 0);
	res = o_stream_send_istream(conn->output, stream->input);
	o_stream_set_max_buffer_size(conn->output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_assert(stream->input->v_offset < stream->size);
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_error("imapc: read(%s) failed: %s",
			i_stream_get_name(stream->input),
			i_stream_get_error(stream->input));
		return -1;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* disconnected */
		return -1;
	}
	i_assert(stream->input->v_offset == stream->size);

	/* finished with the stream */
	i_stream_unref(&stream->input);
	array_pop_front(&cmd->streams);

	i_assert(cmd->send_pos != cmd->data->used);
	return 1;
}

static void imapc_connection_set_selecting(struct imapc_client_mailbox *box)
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
	conn->select_waiting_reply = TRUE;
}

static bool imapc_connection_is_throttled(struct imapc_connection *conn)
{
	timeout_remove(&conn->to_throttle);

	if (conn->throttle_msecs == 0) {
		/* we haven't received [THROTTLED] recently */
		return FALSE;
	}
	if (array_count(&conn->cmd_wait_list) > 0) {
		/* wait until we have received the existing commands' tagged
		   replies to see if we're still throttled */
		return TRUE;
	}
	if (timeval_cmp(&ioloop_timeval, &conn->throttle_end_timeval) >= 0) {
		/* we reached the throttle timeout - send the next command */
		conn->throttle_pending = FALSE;
		return FALSE;
	}

	/* we're still being throttled - wait for it to end */
	conn->to_throttle = timeout_add_absolute(&conn->throttle_end_timeval,
						 imapc_command_send_more, conn);
	return TRUE;
}

static void imapc_command_send_more(struct imapc_connection *conn)
{
	struct imapc_command *const *cmds, *cmd;
	struct imapc_command_reply reply;
	const unsigned char *p, *data;
	unsigned int count, size;
	size_t seek_pos, start_pos, end_pos;
	int ret;

	if (imapc_connection_is_throttled(conn))
		return;

	cmds = array_get(&conn->cmd_send_queue, &count);
	if (count == 0)
		return;
	cmd = cmds[0];

	if ((cmd->flags & IMAPC_COMMAND_FLAG_PRELOGIN) == 0 &&
	    conn->state != IMAPC_CONNECTION_STATE_DONE) {
		/* wait until we're fully connected */
		return;
	}
	if ((cmd->flags & IMAPC_COMMAND_FLAG_LOGOUT) != 0 &&
	    array_count(&conn->cmd_wait_list) > 0) {
		/* wait until existing commands have finished */
		return;
	}
	if (conn->select_waiting_reply) {
		/* wait for SELECT to finish */
		return;
	}
	if (cmd->wait_for_literal) {
		/* wait until we received '+' */
		return;
	}

	i_assert(cmd->send_pos < cmd->data->used);

	if (cmd->box == NULL) {
		/* non-mailbox command */
	} else if (cmd->send_pos == 0 &&
		   (cmd->flags & IMAPC_COMMAND_FLAG_SELECT) != 0) {
		/* SELECT/EXAMINE command */
		imapc_connection_set_selecting(cmd->box);
	} else if (!imapc_client_mailbox_is_opened(cmd->box)) {
		if (cmd->box->reconnecting) {
			/* wait for SELECT/EXAMINE */
			return;
		}
		/* shouldn't normally happen */
		i_zero(&reply);
		reply.text_without_resp = reply.text_full = "Mailbox not open";
		reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;

		array_pop_front(&conn->cmd_send_queue);
		imapc_command_reply_free(cmd, &reply);
		imapc_command_send_more(conn);
		return;
	}

	/* add timeout for commands if there's not one yet
	   (pre-login has its own timeout) */
	if ((cmd->flags & IMAPC_COMMAND_FLAG_LOGOUT) != 0) {
		/* LOGOUT has a shorter timeout */
		timeout_remove(&conn->to);
		conn->to = timeout_add(IMAPC_LOGOUT_TIMEOUT_MSECS,
				       imapc_command_timeout, conn);
	} else if (conn->to == NULL) {
		conn->to = timeout_add(conn->client->set.cmd_timeout_msecs,
				       imapc_command_timeout, conn);
	}

	timeout_reset(conn->to_output);
	if ((ret = imapc_command_try_send_stream(conn, cmd)) == 0)
		return;
	if (ret == -1) {
		i_zero(&reply);
		reply.text_without_resp = reply.text_full = "Mailbox not open";
		reply.state = IMAPC_COMMAND_STATE_DISCONNECTED;

		array_pop_front(&conn->cmd_send_queue);
		imapc_command_reply_free(cmd, &reply);
		imapc_command_send_more(conn);
		return;
	}

	seek_pos = cmd->send_pos;
	if (seek_pos != 0 && ret == -2) {
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

	data = CONST_PTR_OFFSET(cmd->data->data, cmd->send_pos);
	size = end_pos - cmd->send_pos;
	o_stream_nsend(conn->output, data, size);
	cmd->send_pos = end_pos;

	if (cmd->send_pos == cmd->data->used) {
		i_assert(!array_is_created(&cmd->streams) ||
			 array_count(&cmd->streams) == 0);
		imapc_command_send_finished(conn, cmd);
	} else {
		cmd->wait_for_literal = TRUE;
	}
}

static void imapc_connection_send_idle_done(struct imapc_connection *conn)
{
	if ((conn->idling || conn->idle_plus_waiting) && !conn->idle_stopping) {
		conn->idle_stopping = TRUE;
		o_stream_nsend_str(conn->output, "DONE\r\n");
		if (conn->to == NULL) {
			conn->to = timeout_add(conn->client->set.cmd_timeout_msecs,
					       imapc_command_timeout, conn);
		}
	}
}

static void imapc_connection_cmd_send(struct imapc_command *cmd)
{
	struct imapc_connection *conn = cmd->conn;
	struct imapc_command *const *cmds;
	unsigned int i, count;

	imapc_connection_send_idle_done(conn);

	i_assert((cmd->flags & IMAPC_COMMAND_FLAG_RECONNECTED) == 0);

	if ((cmd->flags & IMAPC_COMMAND_FLAG_PRELOGIN) != 0 &&
	    conn->state == IMAPC_CONNECTION_STATE_AUTHENTICATING) {
		/* pre-login commands get inserted before everything else */
		array_push_front(&conn->cmd_send_queue, &cmd);
		imapc_command_send_more(conn);
		return;
	}

	/* add the command just before retried commands */
	cmds = array_get(&conn->cmd_send_queue, &count);
	for (i = count; i > 0; i--) {
		if ((cmds[i-1]->flags & IMAPC_COMMAND_FLAG_RECONNECTED) == 0)
			break;
	}
	array_insert(&conn->cmd_send_queue, i, &cmd, 1);
	imapc_command_send_more(conn);
}

static int imapc_connection_output(struct imapc_connection *conn)
{
	struct imapc_command *const *cmds;
	unsigned int count;
	int ret;

	if (conn->to != NULL)
		timeout_reset(conn->to);

	if ((ret = o_stream_flush(conn->output)) < 0)
		return 1;

	imapc_connection_ref(conn);
	cmds = array_get(&conn->cmd_send_queue, &count);
	if (count > 0) {
		if (imapc_command_get_sending_stream(cmds[0]) != NULL &&
		    !cmds[0]->wait_for_literal) {
			/* we're sending a stream. send more. */
			imapc_command_send_more(conn);
		}
	}
	imapc_connection_unref(&conn);
	return ret;
}

struct imapc_command *
imapc_connection_cmd(struct imapc_connection *conn,
		     imapc_command_callback_t *callback, void *context)
{
	struct imapc_command *cmd;

	cmd = imapc_command_begin(callback, context);
	cmd->conn = conn;
	return cmd;
}

void imapc_command_set_flags(struct imapc_command *cmd,
			     enum imapc_command_flags flags)
{
	cmd->flags = flags;
}

void imapc_command_set_mailbox(struct imapc_command *cmd,
			       struct imapc_client_mailbox *box)
{
	cmd->box = box;
}

bool imapc_command_connection_is_selected(struct imapc_command *cmd)
{
	return cmd->conn->selected_box != NULL ||
		cmd->conn->selecting_box != NULL;
}

void imapc_command_send(struct imapc_command *cmd, const char *cmd_str)
{
	size_t len = strlen(cmd_str);

	cmd->data = str_new(cmd->pool, 6 + len + 2);
	str_printfa(cmd->data, "%u %s\r\n", cmd->tag, cmd_str);
	imapc_connection_cmd_send(cmd);
}

void imapc_command_sendf(struct imapc_command *cmd, const char *cmd_fmt, ...)
{
	va_list args;

	va_start(args, cmd_fmt);
	imapc_command_sendvf(cmd, cmd_fmt, args);
	va_end(args);
}

void imapc_command_sendvf(struct imapc_command *cmd,
			  const char *cmd_fmt, va_list args)
{
	unsigned int i;

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
		case 'p': {
			struct istream *input = va_arg(args, struct istream *);
			struct imapc_command_stream *s;
			uoff_t size;

			if (!array_is_created(&cmd->streams))
				p_array_init(&cmd->streams, cmd->pool, 2);
			if (i_stream_get_size(input, TRUE, &size) < 0)
				size = 0;
			str_printfa(cmd->data, "{%"PRIuUOFF_T"}\r\n", size);
			s = array_append_space(&cmd->streams);
			s->pos = str_len(cmd->data);
			s->size = size;
			s->input = input;
			i_stream_ref(input);
			break;
		}
		case 's': {
			const char *arg = va_arg(args, const char *);

			if (!need_literal(arg))
				imap_append_quoted(cmd->data, arg);
			else if ((cmd->conn->capabilities &
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

			i++;
			i_assert(cmd_fmt[i] == 's');
			str_append(cmd->data, arg);
			break;
		}
		}
	}
	str_append(cmd->data, "\r\n");

	imapc_connection_cmd_send(cmd);
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

void imapc_connection_unselect(struct imapc_client_mailbox *box)
{
	struct imapc_connection *conn = box->conn;

	if (conn->selected_box != NULL || conn->selecting_box != NULL) {
		i_assert(conn->selected_box == box ||
			 conn->selecting_box == box);

		conn->selected_box = NULL;
		conn->selecting_box = NULL;
	}
	imapc_connection_send_idle_done(conn);
	imapc_connection_abort_commands(conn, box, FALSE);
}

struct imapc_client_mailbox *
imapc_connection_get_mailbox(struct imapc_connection *conn)
{
	if (conn->selecting_box != NULL)
		return conn->selecting_box;
	return conn->selected_box;
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
	struct imapc_command *cmd;

	if (array_count(&conn->cmd_send_queue) != 0 ||
	    array_count(&conn->cmd_wait_list) != 0 ||
	    conn->idling || conn->idle_plus_waiting ||
	    (conn->capabilities & IMAPC_CAPABILITY_IDLE) == 0)
		return;

	cmd = imapc_connection_cmd(conn, imapc_connection_idle_callback, conn);
	cmd->idle = TRUE;
	imapc_command_send(cmd, "IDLE");
}
