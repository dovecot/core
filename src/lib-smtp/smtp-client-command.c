/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "array.h"
#include "str.h"
#include "llist.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "ostream-dot.h"
#include "smtp-common.h"
#include "smtp-syntax.h"
#include "smtp-params.h"
#include "smtp-client-private.h"

/*
 * Logging
 */

static inline void ATTR_FORMAT(2, 3)
smtp_client_command_debug(struct smtp_client_command *cmd,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	e_debug(cmd->event, "%s", t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 *
 */

static const char *
smtp_client_command_get_name(struct smtp_client_command *cmd)
{
	const unsigned char *p, *pend;

	if (cmd->name != NULL)
		return cmd->name;

	if (cmd->plug)
		return NULL;
	if (cmd->data == NULL || cmd->data->used == 0)
		return NULL;

	p = cmd->data->data;
	pend = p + cmd->data->used;
	for (;p < pend; p++) {
		if (*p == ' ' || *p == '\r' || *p == '\n')
			break;
	}
	cmd->name = p_strdup(cmd->pool,
		t_str_ucase(t_strdup_until(cmd->data->data, p)));
	return cmd->name;
}

static const char *
smtp_client_command_get_label(struct smtp_client_command *cmd)
{
	if (cmd->plug)
		return "[plug]";
	if (cmd->data == NULL || cmd->data->used == 0) {
		if (!cmd->has_stream)
			return "[empty]";
		return "[data]";
	}
	return smtp_client_command_get_name(cmd);
}

static void
smtp_client_command_update_event(struct smtp_client_command *cmd)
{
	event_add_str(cmd->event, "name", smtp_client_command_get_name(cmd));
	event_set_append_log_prefix(cmd->event,
		t_strdup_printf("command %s: ",
				smtp_client_command_get_label(cmd)));
}

static struct smtp_client_command *
smtp_client_command_create(struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	smtp_client_command_callback_t *callback, void *context)
{
	struct smtp_client_command *cmd;
	pool_t pool;

	pool = pool_alloconly_create("smtp client command", 2048);
	cmd = p_new(pool, struct smtp_client_command, 1);
	cmd->pool = pool;
	cmd->refcount = 1;
	cmd->conn = conn;
	cmd->flags = flags;
	cmd->replies_expected = 1;
	cmd->callback = callback;
	cmd->context = context;
	cmd->event = event_create(conn->event);
	smtp_client_command_update_event(cmd);
	return cmd;
}

#undef smtp_client_command_new
struct smtp_client_command *
smtp_client_command_new(struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	smtp_client_command_callback_t *callback, void *context)
{
	i_assert(callback != NULL);
	return smtp_client_command_create(conn, flags, callback, context);
}

struct smtp_client_command *
smtp_client_command_plug(struct smtp_client_connection *conn,
	struct smtp_client_command *after)
{
	struct smtp_client_command *cmd;

	cmd = smtp_client_command_create(conn, 0, NULL, NULL);
	cmd->plug = TRUE;
	smtp_client_command_submit_after(cmd, after);
	return cmd;
}

void smtp_client_command_ref(struct smtp_client_command *cmd)
{
	cmd->refcount++;
}

void smtp_client_command_unref(struct smtp_client_command **_cmd)
{
	struct smtp_client_command *cmd = *_cmd;
	struct smtp_client_connection *conn = cmd->conn;

	i_assert(cmd->refcount > 0);
	if (--cmd->refcount > 0)
		return;

	smtp_client_command_debug(cmd, "Destroy "
		"(%u commands pending, %u commands queued)",
		conn->cmd_wait_list_count, conn->cmd_send_queue_count);

	i_assert(cmd->state >= SMTP_CLIENT_COMMAND_STATE_FINISHED);

	i_stream_unref(&cmd->stream);
	event_unref(&cmd->event);
	pool_unref(&cmd->pool);
	*_cmd = NULL;
}

bool smtp_client_command_name_equals(struct smtp_client_command *cmd,
				     const char *name)
{
	const unsigned char *data;
	size_t name_len, data_len;

	if (cmd->data == NULL)
		return FALSE;

	name_len = strlen(name);
	data = cmd->data->data;
	data_len = cmd->data->used;

	if (data_len < name_len ||
		i_memcasecmp(data, name, name_len) != 0)
		return FALSE;
	return (data_len == name_len ||
		data[name_len] == ' ' || data[name_len] == '\r');
}

void smtp_client_command_lock(struct smtp_client_command *cmd)
{
	if (cmd->plug)
		return;
	cmd->locked = TRUE;
}

void smtp_client_command_unlock(struct smtp_client_command *cmd)
{
	if (cmd->plug)
		return;
	if (cmd->locked) {
		cmd->locked = FALSE;
		if (!cmd->conn->corked)
			smtp_client_connection_trigger_output(cmd->conn);
	}
}

void smtp_client_command_abort(struct smtp_client_command **_cmd)
{
	struct smtp_client_command *cmd = *_cmd;
	struct smtp_client_connection *conn = cmd->conn;
	enum smtp_client_command_state state = cmd->state;
	bool disconnected =
		(conn->state == SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED);
	bool waslocked =
		(state >= SMTP_CLIENT_COMMAND_STATE_SUBMITTED) &&
		(cmd->locked || cmd->plug);

	*_cmd = NULL;

	smtp_client_command_drop_callback(cmd);

	if ((!disconnected && !cmd->plug && cmd->aborting) ||
		state >= SMTP_CLIENT_COMMAND_STATE_FINISHED)
		return;

	if (disconnected || state <= SMTP_CLIENT_COMMAND_STATE_SUBMITTED) {
		smtp_client_command_debug(cmd, "Abort");
		cmd->state = SMTP_CLIENT_COMMAND_STATE_ABORTED;
	} else {
		smtp_client_command_debug(cmd, "Abort (already sent)");
		i_assert(state < SMTP_CLIENT_COMMAND_STATE_FINISHED);
		cmd->aborting = TRUE;
	}
	cmd->locked = FALSE;

	i_assert(!cmd->plug || state <= SMTP_CLIENT_COMMAND_STATE_SUBMITTED);

	switch (state) {
	case SMTP_CLIENT_COMMAND_STATE_NEW:
		if (cmd->delaying_failure) {
			DLLIST_REMOVE(&conn->cmd_fail_list, cmd);
			if (conn->cmd_fail_list == NULL)
				timeout_remove(&conn->to_cmd_fail);
		}
		break;
	case SMTP_CLIENT_COMMAND_STATE_SENDING:
		if (!disconnected) {
			/* it is being sent; cannot truly abort it now */
			break;
		}
		/* fall through */
	case SMTP_CLIENT_COMMAND_STATE_SUBMITTED:
		/* not yet sent */
		smtp_client_command_debug(cmd, "Removed from send queue");
		i_assert(conn->cmd_send_queue_count > 0);
		DLLIST2_REMOVE(&conn->cmd_send_queue_head,
			&conn->cmd_send_queue_tail, cmd);
		i_assert(conn->cmd_send_queue_count > 1 ||
			(cmd->prev == NULL && cmd->next == NULL));
		conn->cmd_send_queue_count--;
		break;
	case SMTP_CLIENT_COMMAND_STATE_WAITING:
		if (!disconnected) {
			/* we're expecting a reply; cannot truly abort it now */
			break;
		}
		smtp_client_command_debug(cmd, "Removed from wait list");
		i_assert(conn->cmd_wait_list_count > 0);
		DLLIST2_REMOVE(&conn->cmd_wait_list_head,
			&conn->cmd_wait_list_tail, cmd);
		conn->cmd_wait_list_count--;
		break;
	default:
		i_unreached();
	}

	if (cmd->abort_callback != NULL) {
		cmd->abort_callback(cmd->abort_context);
		cmd->abort_callback = NULL;
	}

	if (disconnected || cmd->plug ||
		state <= SMTP_CLIENT_COMMAND_STATE_SUBMITTED) {
		/* can only destroy it when it is not pending */
		smtp_client_command_unref(&cmd);
	}

	if (!disconnected && waslocked && !conn->corked)
		smtp_client_connection_trigger_output(conn);
}

void smtp_client_command_drop_callback(struct smtp_client_command *cmd)
{
	cmd->callback = NULL;
	cmd->context = NULL;
}

void smtp_client_command_fail_reply(struct smtp_client_command **_cmd,
				    const struct smtp_reply *reply)
{
	struct smtp_client_command *cmd = *_cmd, *tmp_cmd;
	struct smtp_client_connection *conn = cmd->conn;
	enum smtp_client_command_state state = cmd->state;
	smtp_client_command_callback_t *callback = cmd->callback;

	*_cmd = NULL;

	if (state >= SMTP_CLIENT_COMMAND_STATE_FINISHED)
		return;

	if (cmd->delay_failure) {
		i_assert(cmd->delayed_failure == NULL);
		i_assert(state < SMTP_CLIENT_COMMAND_STATE_SUBMITTED);

		smtp_client_command_debug(cmd, "Fail (delay)");

		cmd->delayed_failure = smtp_reply_clone(cmd->pool, reply);
		cmd->delaying_failure = TRUE;
		if (conn->to_cmd_fail == NULL) {
			conn->to_cmd_fail = timeout_add_short(0,
				smtp_client_commands_fail_delayed, conn);
		}
		DLLIST_PREPEND(&conn->cmd_fail_list, cmd);
		return;
	}

	cmd->callback = NULL;

	smtp_client_connection_ref(conn);
	smtp_client_command_ref(cmd);

	if (!cmd->aborting) {
		smtp_client_command_debug(cmd, "Fail");
		if (callback != NULL)
			(void)callback(reply, cmd->context);
	}

	tmp_cmd = cmd;
	smtp_client_command_abort(&tmp_cmd);

	smtp_client_command_unref(&cmd);
	smtp_client_connection_unref(&conn);
}

void smtp_client_command_fail(struct smtp_client_command **_cmd,
			      unsigned int status, const char *error)
{
	struct smtp_reply reply;
	const char *text_lines[] = {error, NULL};

	i_zero(&reply);
	reply.status = status;
	reply.text_lines = text_lines;
	reply.enhanced_code.x = 9;

	smtp_client_command_fail_reply(_cmd, &reply);
}

static void
smtp_client_command_fail_delayed(struct smtp_client_command **_cmd)
{
	struct smtp_client_command *cmd = *_cmd;

	smtp_client_command_debug(cmd, "Fail delayed");

	i_assert(!cmd->delay_failure);
	i_assert(cmd->state < SMTP_CLIENT_COMMAND_STATE_FINISHED);
	smtp_client_command_fail_reply(_cmd, cmd->delayed_failure);
}

void smtp_client_commands_list_abort(struct smtp_client_command *cmds_list,
				     unsigned int cmds_list_count)
{
	struct smtp_client_command *cmd;
	ARRAY(struct smtp_client_command *) cmds_arr;
	struct smtp_client_command **cmds;
	unsigned int count, i;

	if (cmds_list == NULL)
		return;
	i_assert(cmds_list_count > 0);

	/* copy the array and reference the commands to be robust against more
	   than one command disappearing from the list */
	t_array_init(&cmds_arr, cmds_list_count);
	for (cmd = cmds_list; cmd != NULL; cmd = cmd->next) {
		smtp_client_command_ref(cmd);
		array_push_back(&cmds_arr, &cmd);
	}

	cmds = array_get_modifiable(&cmds_arr, &count);
	for (i = 0; i < count; i++) {
		cmd = cmds[i];
		/* fail the reply */
		smtp_client_command_abort(&cmds[i]);
		/* drop our reference */
		smtp_client_command_unref(&cmd);
	}
}

void smtp_client_commands_list_fail_reply(
	struct smtp_client_command *cmds_list, unsigned int cmds_list_count,
	const struct smtp_reply *reply)
{
	struct smtp_client_command *cmd;
	ARRAY(struct smtp_client_command *) cmds_arr;
	struct smtp_client_command **cmds;
	unsigned int count, i;

	if (cmds_list == NULL)
		return;
	i_assert(cmds_list_count > 0);

	/* copy the array and reference the commands to be robust against more
	   than one command disappearing from the list */
	t_array_init(&cmds_arr, cmds_list_count);
	for (cmd = cmds_list; cmd != NULL; cmd = cmd->next) {
		smtp_client_command_ref(cmd);
		array_push_back(&cmds_arr, &cmd);
	}

	cmds = array_get_modifiable(&cmds_arr, &count);
	for (i = 0; i < count; i++) {
		cmd = cmds[i];
		/* fail the reply */
		smtp_client_command_fail_reply(&cmds[i], reply);
		/* drop our reference */
		smtp_client_command_unref(&cmd);
	}
}

void smtp_client_commands_abort_delayed(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd;

	timeout_remove(&conn->to_cmd_fail);

	cmd = conn->cmd_fail_list;
	conn->cmd_fail_list = NULL;
	while (cmd != NULL) {
		struct smtp_client_command *cmd_next = cmd->next;

		cmd->delaying_failure = FALSE;
		smtp_client_command_abort(&cmd);
		cmd = cmd_next;
	}
}

void smtp_client_commands_fail_delayed(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd;

	timeout_remove(&conn->to_cmd_fail);

	cmd = conn->cmd_fail_list;
	conn->cmd_fail_list = NULL;
	while (cmd != NULL) {
		struct smtp_client_command *cmd_next = cmd->next;

		cmd->delaying_failure = FALSE;
		smtp_client_command_fail_delayed(&cmd);
		cmd = cmd_next;
	}
}

void smtp_client_command_set_abort_callback(struct smtp_client_command *cmd,
	void (*callback)(void *context), void *context)
{
	cmd->abort_callback = callback;
	cmd->abort_context = context;
}

void smtp_client_command_set_sent_callback(struct smtp_client_command *cmd,
	void (*callback)(void *context), void *context)
{
	cmd->sent_callback = callback;
	cmd->sent_context = context;
}

void smtp_client_command_set_replies(struct smtp_client_command *cmd,
	unsigned int replies)
{
	i_assert(cmd->replies_expected == 1 ||
		cmd->replies_expected == replies);
	i_assert(replies > 0);
	i_assert(cmd->replies_seen <= 1);
	cmd->replies_expected = replies;
}

static void
smtp_client_command_sent(struct smtp_client_command *cmd)
{
	if (cmd->data == NULL)
		smtp_client_command_debug(cmd, "Sent");
	else {
		i_assert(str_len(cmd->data) > 2);
		str_truncate(cmd->data, str_len(cmd->data)-2);
		smtp_client_command_debug(cmd, "Sent: %s", str_c(cmd->data));
	}

	if (smtp_client_command_name_equals(cmd, "QUIT"))
		cmd->conn->sent_quit = TRUE;

	if (cmd->sent_callback != NULL) {
		cmd->sent_callback(cmd->sent_context);
		cmd->sent_callback = NULL;
	}
}

static int
smtp_client_command_finish_dot_stream(struct smtp_client_command *cmd)
{
	struct smtp_client_connection *conn = cmd->conn;
	int ret;

	i_assert(cmd->stream_dot);
	i_assert(conn->dot_output != NULL);

	/* this concludes the dot stream with CRLF.CRLF */
	if ((ret=o_stream_finish(conn->dot_output)) < 0) {
		o_stream_unref(&conn->dot_output);
		smtp_client_connection_handle_output_error(conn);
		return -1;
	}
	if (ret == 0)
		return 0;
	o_stream_unref(&conn->dot_output);
	return 1;
}

static void smtp_client_command_payload_input(struct smtp_client_command *cmd)
{
	struct smtp_client_connection *conn = cmd->conn;

	io_remove(&conn->io_cmd_payload);

	smtp_client_connection_trigger_output(conn);
}

static int
smtp_client_command_send_stream(struct smtp_client_command *cmd)
{
	struct smtp_client_connection *conn = cmd->conn;
	struct istream *stream = cmd->stream;
	struct ostream *output = conn->conn.output;
	enum ostream_send_istream_result res;
	int ret;

	io_remove(&conn->io_cmd_payload);

	if (cmd->stream_finished) {
		if ((ret=smtp_client_command_finish_dot_stream(cmd)) <= 0)
			return ret;
		/* done sending payload */
		smtp_client_command_debug(cmd, "Finished sending payload");
		i_stream_unref(&cmd->stream);
		return 1;
	}
	if (cmd->stream_dot) {
		if (conn->dot_output == NULL)
			conn->dot_output = o_stream_create_dot(output, FALSE);
		output = conn->dot_output;
	}

	/* we're sending the stream now */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(output, stream);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		i_assert(cmd->stream_size == 0 ||
			stream->v_offset == cmd->stream_size);
		/* finished with the stream */
		smtp_client_command_debug(cmd,
			"Finished reading payload stream");
		cmd->stream_finished = TRUE;
		if (cmd->stream_dot) {
			if ((ret=smtp_client_command_finish_dot_stream(cmd)) <= 0)
				return ret;
		}
		/* done sending payload */
		smtp_client_command_debug(cmd, "Finished sending payload");
		i_stream_unref(&cmd->stream);
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		/* input is blocking (client needs to act; disable timeout) */
		conn->io_cmd_payload = io_add_istream(
			stream, smtp_client_command_payload_input, cmd);
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		smtp_client_command_debug(cmd, "Partially sent payload");
		i_assert(cmd->stream_size == 0 ||
			stream->v_offset < cmd->stream_size);
		return 0;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:

		/* the provided payload stream is broken;
		   fail this command separately */
		e_error(cmd->event, "read(%s) failed: %s",
			i_stream_get_name(stream), i_stream_get_error(stream));
		smtp_client_command_fail(&cmd,
			SMTP_CLIENT_COMMAND_ERROR_BROKEN_PAYLOAD,
			"Broken payload stream");
		/* we're in the middle of sending a command, so the connection
		   will also have to be aborted */
		o_stream_unref(&conn->dot_output);
		smtp_client_connection_fail(conn,
			SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST,
			"Broken payload stream");
		return -1;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* normal connection failure */
		o_stream_unref(&conn->dot_output);
		smtp_client_connection_handle_output_error(conn);
		return -1;
	}
	i_unreached();
}

static int
smtp_client_command_send_line(struct smtp_client_command *cmd)
{
	struct smtp_client_connection *conn = cmd->conn;
	const char *data;
	size_t size;
	ssize_t sent;

	if (cmd->data == NULL)
		return 1;

	while (cmd->send_pos < cmd->data->used) {
		data = CONST_PTR_OFFSET(cmd->data->data, cmd->send_pos);
		size = cmd->data->used - cmd->send_pos;
		if ((sent=o_stream_send(conn->conn.output, data, size)) <= 0) {
			if (sent < 0) {
				smtp_client_connection_handle_output_error(conn);
				return -1;
			}
			smtp_client_command_debug(cmd,
				"Blocked while sending");
			return 0;
		}
		cmd->send_pos += sent;
	}

	i_assert(cmd->send_pos == cmd->data->used);
	return 1;
}

static bool
smtp_client_command_pipeline_is_open(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd = conn->cmd_send_queue_head;

	if (cmd == NULL)
		return TRUE;

	if (cmd->plug) {
		smtp_client_command_debug(cmd, "Pipeline is plugged");
		return FALSE;
	}

	if (conn->state < SMTP_CLIENT_CONNECTION_STATE_READY &&
	    (cmd->flags & SMTP_CLIENT_COMMAND_FLAG_PRELOGIN) == 0) {
		/* wait until we're fully connected */
		smtp_client_command_debug(cmd,
			"Connection not ready [state=%s]",
			smtp_client_connection_state_names[conn->state]);
		return FALSE;
	}

	cmd = conn->cmd_wait_list_head;
	if (cmd != NULL &&
	    (conn->caps.standard & SMTP_CAPABILITY_PIPELINING) == 0) {
		/* cannot pipeline; wait for reply */
		smtp_client_command_debug(cmd, "Pipeline occupied");
		return FALSE;
	}
	while (cmd != NULL) {
		if ((conn->caps.standard & SMTP_CAPABILITY_PIPELINING) == 0 ||
		    (cmd->flags & SMTP_CLIENT_COMMAND_FLAG_PIPELINE) == 0 ||
		    cmd->locked) {
			/* cannot pipeline with previous command;
			   wait for reply */
			smtp_client_command_debug(cmd, "Pipeline blocked");
			return FALSE;
		}
		cmd = cmd->next;
	}

	return TRUE;
}

static void smtp_cient_command_wait(struct smtp_client_command *cmd)
{
	struct smtp_client_connection *conn = cmd->conn;

	/* move command to wait list. */
	i_assert(conn->cmd_send_queue_count > 0);
	i_assert(conn->cmd_send_queue_count > 1 ||
		(cmd->prev == NULL && cmd->next == NULL));
	DLLIST2_REMOVE(&conn->cmd_send_queue_head,
		       &conn->cmd_send_queue_tail, cmd);
	conn->cmd_send_queue_count--;
	DLLIST2_APPEND(&conn->cmd_wait_list_head,
		       &conn->cmd_wait_list_tail, cmd);
	conn->cmd_wait_list_count++;
}

static int smtp_client_command_do_send_more(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd;
	int ret;

	if (conn->cmd_streaming != NULL) {
		cmd = conn->cmd_streaming;
		i_assert(cmd->stream != NULL);
	} else {
		/* check whether we can send anything */
		cmd = conn->cmd_send_queue_head;
		if (cmd == NULL)
			return 0;
		if (!smtp_client_command_pipeline_is_open(conn))
			return 0;

		cmd->state = SMTP_CLIENT_COMMAND_STATE_SENDING;
		conn->sending_command = TRUE;

		if ((ret=smtp_client_command_send_line(cmd)) <= 0)
			return ret;

		/* command line sent. move command to wait list. */
		smtp_cient_command_wait(cmd);
		cmd->state = SMTP_CLIENT_COMMAND_STATE_WAITING;
	}

	if (cmd->stream != NULL &&
	    (ret=smtp_client_command_send_stream(cmd)) <= 0) {
		if (ret < 0)
			return -1;
		smtp_client_command_debug(cmd, "Blocked while sending payload");
		conn->cmd_streaming = cmd;
		return 0;
	}

	conn->cmd_streaming = NULL;
	conn->sending_command = FALSE;
	smtp_client_command_sent(cmd);
	return 1;
}

int smtp_client_command_send_more(struct smtp_client_connection *conn)
{
	int ret;

	while ((ret=smtp_client_command_do_send_more(conn)) > 0);
	if (ret < 0)
		return -1;

	smtp_client_connection_update_cmd_timeout(conn);
	return ret;
}

static void
smtp_client_command_disconnected(struct smtp_client_connection *conn)
{
	smtp_client_connection_fail(conn,
		SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST, "Disconnected");
}

static void
smtp_client_command_insert_prioritized(struct smtp_client_command *cmd,
	enum smtp_client_command_flags flag)
{
	struct smtp_client_connection *conn = cmd->conn;
	struct smtp_client_command *cmd_cur, *cmd_prev;

	cmd_cur = conn->cmd_send_queue_head;
	if (cmd_cur == NULL ||
		(cmd_cur->flags & flag) == 0) {
		DLLIST2_PREPEND(&conn->cmd_send_queue_head,
			&conn->cmd_send_queue_tail, cmd);
		conn->cmd_send_queue_count++;
	} else {
		cmd_prev = cmd_cur;
		cmd_cur = cmd_cur->next;
		while (cmd_cur != NULL &&
			(cmd_cur->flags & flag) != 0) {
			cmd_prev = cmd_cur;
			cmd_cur = cmd_cur->next;
		}
		DLLIST2_INSERT_AFTER(&conn->cmd_send_queue_head,
			&conn->cmd_send_queue_tail, cmd_prev, cmd);
		conn->cmd_send_queue_count++;
	}
}

void
smtp_client_command_submit_after(struct smtp_client_command *cmd,
	struct smtp_client_command *after)
{
	struct smtp_client_connection *conn = cmd->conn;

	i_assert(after == NULL || cmd->conn == after->conn);

	smtp_client_command_update_event(cmd);
	cmd->state = SMTP_CLIENT_COMMAND_STATE_SUBMITTED;

	if (smtp_client_command_name_equals(cmd, "EHLO"))
		cmd->ehlo = TRUE;

	if (conn->state == SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED) {
		/* Add commands to send queue for delayed failure reply
		   from ioloop */
		DLLIST2_APPEND(&conn->cmd_send_queue_head,
			&conn->cmd_send_queue_tail, cmd);
		conn->cmd_send_queue_count++;
		if (conn->to_commands == NULL) {
			conn->to_commands = timeout_add_short(0,
				smtp_client_command_disconnected, conn);
		}
		smtp_client_command_debug(cmd,
			"Submitted, but disconnected");
		return;
	}

	if (cmd->data != NULL)
		str_append(cmd->data, "\r\n");

	if ((cmd->flags & SMTP_CLIENT_COMMAND_FLAG_PRELOGIN) != 0 &&
	    conn->state < SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* pre-login commands get inserted before everything else */
		smtp_client_command_insert_prioritized(cmd,
			SMTP_CLIENT_COMMAND_FLAG_PRELOGIN);
		if (!conn->corked)
			smtp_client_connection_trigger_output(conn);
		smtp_client_command_debug(cmd, "Submitted with priority");
		return;
	}

	if (after != NULL) {
		if (after->state >= SMTP_CLIENT_COMMAND_STATE_WAITING) {
			/* not in the send queue anymore; just prepend */
			DLLIST2_PREPEND(&conn->cmd_send_queue_head,
				&conn->cmd_send_queue_tail, cmd);
			conn->cmd_send_queue_count++;
		} else {
			/* insert after indicated command */
			DLLIST2_INSERT_AFTER(&conn->cmd_send_queue_head,
				&conn->cmd_send_queue_tail, after, cmd);
			conn->cmd_send_queue_count++;
		}
	} else if ((cmd->flags & SMTP_CLIENT_COMMAND_FLAG_PRIORITY) != 0) {
		/* insert at beginning of queue for priority commands */
		smtp_client_command_insert_prioritized
			(cmd, SMTP_CLIENT_COMMAND_FLAG_PRIORITY);
	} else {
		/* just append at end of queue */
		DLLIST2_APPEND(&conn->cmd_send_queue_head,
			&conn->cmd_send_queue_tail, cmd);
		conn->cmd_send_queue_count++;
	}

	if (conn->state >= SMTP_CLIENT_CONNECTION_STATE_READY)
		smtp_client_connection_start_cmd_timeout(conn);

	if (!conn->corked)
		smtp_client_connection_trigger_output(conn);
	smtp_client_command_debug(cmd, "Submitted");
}

void smtp_client_command_submit(struct smtp_client_command *cmd)
{
	smtp_client_command_submit_after(cmd, NULL);
}

void smtp_client_command_set_flags(struct smtp_client_command *cmd,
			     enum smtp_client_command_flags flags)
{
	cmd->flags = flags;
}

void smtp_client_command_write(struct smtp_client_command *cmd,
			       const char *cmd_str)
{
	unsigned int len = strlen(cmd_str);

	i_assert(cmd->state < SMTP_CLIENT_COMMAND_STATE_SUBMITTED);
	if (cmd->data == NULL)
		cmd->data = str_new(cmd->pool, len + 2);
	str_append(cmd->data, cmd_str);
}

void smtp_client_command_printf(struct smtp_client_command *cmd,
				const char *cmd_fmt, ...)
{
	va_list args;

	va_start(args, cmd_fmt);
	smtp_client_command_vprintf(cmd, cmd_fmt, args);
	va_end(args);
}

void
smtp_client_command_vprintf(struct smtp_client_command *cmd,
			    const char *cmd_fmt, va_list args)
{
	if (cmd->data == NULL)
		cmd->data = str_new(cmd->pool, 128);
	str_vprintfa(cmd->data, cmd_fmt, args);
}

void
smtp_client_command_set_stream(struct smtp_client_command *cmd,
			       struct istream *input, bool dot)
{
	int ret;

	cmd->stream = input;
	i_stream_ref(input);

	if ((ret=i_stream_get_size(input, TRUE, &cmd->stream_size)) <= 0) {
		if (ret < 0) {
			e_error(cmd->event, "i_stream_get_size(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
		}
		/* size must be known if stream is to be sent in chunks */
		i_assert(dot);
		cmd->stream_size = 0;
	}

	cmd->stream_dot = dot;
	cmd->has_stream = TRUE;
}

int
smtp_client_command_input_reply(struct smtp_client_command *cmd,
				const struct smtp_reply *reply)
{
	struct smtp_client_connection *conn = cmd->conn;
	bool finished;

	i_assert(cmd->replies_seen < cmd->replies_expected);
	finished = (++cmd->replies_seen == cmd->replies_expected);

	smtp_client_command_debug(cmd, "Got reply (%u/%u): %s "
		"(%u commands pending, %u commands queued)",
		cmd->replies_seen, cmd->replies_expected,
		smtp_reply_log(reply), conn->cmd_wait_list_count,
		conn->cmd_send_queue_count);

	if (finished) {
		i_assert(conn->cmd_wait_list_count > 0);
		DLLIST2_REMOVE(&conn->cmd_wait_list_head,
			&conn->cmd_wait_list_tail, cmd);
		conn->cmd_wait_list_count--;
		if (cmd->aborting)
			cmd->state = SMTP_CLIENT_COMMAND_STATE_ABORTED;
		else if (cmd->state != SMTP_CLIENT_COMMAND_STATE_ABORTED)
			cmd->state = SMTP_CLIENT_COMMAND_STATE_FINISHED;

		smtp_client_connection_update_cmd_timeout(conn);
	}

	if (!cmd->aborting && cmd->callback != NULL)
		cmd->callback(reply, cmd->context);

	if (finished) {
		smtp_client_command_drop_callback(cmd);
		smtp_client_command_unref(&cmd);
		smtp_client_connection_trigger_output(conn);
	}
	return 1;
}

enum smtp_client_command_state
smtp_client_command_get_state(struct smtp_client_command *cmd)
{
	return cmd->state;
}

/*
 * Standard commands
 */

/* NOTE: Pipelining is only enabled for certain commands:

   From RFC 2920, Section 3.1:

   Once the client SMTP has confirmed that support exists for the
   pipelining extension, the client SMTP may then elect to transmit
   groups of SMTP commands in batches without waiting for a response to
   each individual command. In particular, the commands RSET, MAIL FROM,
   SEND FROM, SOML FROM, SAML FROM, and RCPT TO can all appear anywhere
   in a pipelined command group.  The EHLO, DATA, VRFY, EXPN, TURN,
   QUIT, and NOOP commands can only appear as the last command in a
   group since their success or failure produces a change of state which
   the client SMTP must accommodate. (NOOP is included in this group so
   it can be used as a synchronization point.)

   Additional commands added by other SMTP extensions may only appear as
   the last command in a group unless otherwise specified by the
   extensions that define the commands.
 */

/* NOOP */

#undef smtp_client_command_noop_submit_after
struct smtp_client_command *
smtp_client_command_noop_submit_after(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct smtp_client_command *after,
	smtp_client_command_callback_t *callback, void *context)
{
	struct smtp_client_command *cmd;

	cmd = smtp_client_command_new(conn, flags, callback, context);
	smtp_client_command_write(cmd, "NOOP");
	smtp_client_command_submit_after(cmd, after);
	return cmd;
}

#undef smtp_client_command_noop_submit
struct smtp_client_command *
smtp_client_command_noop_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	smtp_client_command_callback_t *callback, void *context)
{
	return smtp_client_command_noop_submit_after
		(conn, flags, NULL, callback, context);
}

/* VRFY */

#undef smtp_client_command_vrfy_submit_after
struct smtp_client_command *
smtp_client_command_vrfy_submit_after(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct smtp_client_command *after,
	const char *param, smtp_client_command_callback_t *callback,
	void *context)
{
	struct smtp_client_command *cmd;

	cmd = smtp_client_command_new(conn,
		flags, callback, context);
	smtp_client_command_write(cmd, "VRFY ");
	smtp_string_write(cmd->data, param);
	smtp_client_command_submit_after(cmd, after);
	return cmd;
}

#undef smtp_client_command_vrfy_submit
struct smtp_client_command *
smtp_client_command_vrfy_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	const char *param, smtp_client_command_callback_t *callback,
	void *context)
{
	return smtp_client_command_vrfy_submit_after
		(conn, flags, NULL, param, callback, context);
}

/* RSET */

#undef smtp_client_command_rset_submit_after
struct smtp_client_command *
smtp_client_command_rset_submit_after(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct smtp_client_command *after,
	smtp_client_command_callback_t *callback, void *context)
{
	struct smtp_client_command *cmd;

	cmd = smtp_client_command_new(conn,
		flags | SMTP_CLIENT_COMMAND_FLAG_PIPELINE,
		callback, context);
	smtp_client_command_write(cmd, "RSET");
	smtp_client_command_submit_after(cmd, after);
	return cmd;
}

#undef smtp_client_command_rset_submit
struct smtp_client_command *
smtp_client_command_rset_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	smtp_client_command_callback_t *callback, void *context)
{
	return smtp_client_command_rset_submit_after
		(conn, flags, NULL, callback, context);
}

/* MAIL FROM: */

#undef smtp_client_command_mail_submit
struct smtp_client_command *
smtp_client_command_mail_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	const struct smtp_address *from,
	const struct smtp_params_mail *params,
	smtp_client_command_callback_t *callback, void *context)
{
	struct smtp_client_command *cmd;

	smtp_client_connection_send_xclient(conn);

	cmd = smtp_client_command_new(conn,
		flags | SMTP_CLIENT_COMMAND_FLAG_PIPELINE,
		callback, context);
	smtp_client_command_printf(cmd, "MAIL FROM:<%s>",
		smtp_address_encode(from));
	if (params != NULL) {
		size_t orig_len = str_len(cmd->data);
		str_append_c(cmd->data, ' ');
		smtp_params_mail_write(cmd->data, conn->caps.standard, params);
		if (str_len(cmd->data) == orig_len + 1)
			str_truncate(cmd->data, orig_len);

	}
	smtp_client_command_submit(cmd);
	return cmd;
}

/* RCPT TO: */

#undef smtp_client_command_rcpt_submit_after
struct smtp_client_command *
smtp_client_command_rcpt_submit_after(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct smtp_client_command *after,
	const struct smtp_address *to,
	const struct smtp_params_rcpt *params,
	smtp_client_command_callback_t *callback, void *context)
{
	struct smtp_client_command *cmd;

	cmd = smtp_client_command_new(conn,
		flags | SMTP_CLIENT_COMMAND_FLAG_PIPELINE,
		callback, context);
	smtp_client_command_printf(cmd, "RCPT TO:<%s>",
		smtp_address_encode(to));
	if (params != NULL) {
		size_t orig_len = str_len(cmd->data);
		str_append_c(cmd->data, ' ');
		smtp_params_rcpt_write(cmd->data, conn->caps.standard, params);
		if (str_len(cmd->data) == orig_len + 1)
			str_truncate(cmd->data, orig_len);
	}
	smtp_client_command_submit_after(cmd, after);
	return cmd;
}

#undef smtp_client_command_rcpt_submit
struct smtp_client_command *
smtp_client_command_rcpt_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	const struct smtp_address *from,
	const struct smtp_params_rcpt *params,
	smtp_client_command_callback_t *callback, void *context)
{
	return smtp_client_command_rcpt_submit_after
		(conn, flags, NULL, from, params, callback, context);
}

/* DATA or BDAT */

struct _cmd_data_context {
	struct smtp_client_connection *conn;
	pool_t pool;

	struct smtp_client_command *cmd_data, *cmd_first;
	ARRAY(struct smtp_client_command *) cmds;

	struct istream *data;
	uoff_t data_offset, data_left;
};

static void
_cmd_bdat_send_chunks(struct _cmd_data_context *ctx,
	struct smtp_client_command *after);

static void _cmd_data_context_free(struct _cmd_data_context *ctx)
{
	if (ctx->cmd_data != NULL) {
		/* abort the main (possibly unsubmitted) data command */
		smtp_client_command_set_abort_callback(ctx->cmd_data,
			NULL, NULL);
		ctx->cmd_data = NULL;
	}
	i_stream_unref(&ctx->data);
}

static void _cmd_data_abort(struct _cmd_data_context *ctx)
{
	struct smtp_client_command **cmds;
	unsigned int count, i;

	/* drop all pending commands */
	cmds = array_get_modifiable(&ctx->cmds, &count);
	for (i = 0; i < count; i++) {
		smtp_client_command_set_abort_callback(cmds[i], NULL, NULL);
		smtp_client_command_abort(&cmds[i]);
	}
}

static void _cmd_data_abort_cb(void *context)
{
	struct _cmd_data_context *ctx = (struct _cmd_data_context *)context;

	/* the main (possibly unsubmitted) data command got aborted */
	_cmd_data_abort(ctx);
	_cmd_data_context_free(ctx);
}

static void _cmd_data_error(struct _cmd_data_context *ctx,
	const struct smtp_reply *reply)
{
	struct smtp_client_command *cmd = ctx->cmd_data;

	if (cmd != NULL) {
		/* fail the main (possibly unsubmitted) data command so that
		   the caller gets notified */
		smtp_client_command_fail_reply(&cmd, reply);
	}
}

static void _cmd_data_cb(const struct smtp_reply *reply,
	      void *context)
{
	struct _cmd_data_context *ctx = (struct _cmd_data_context *)context;
	struct smtp_client_command *const *cmds, *cmd;
	unsigned int count;

	/* got DATA reply; one command must be pending */
	cmds = array_get(&ctx->cmds, &count);
	i_assert(count > 0);

	if (reply->status == 354) {
		/* submit second stage: which is a command with only a stream */
		cmd = ctx->cmd_data;
		smtp_client_command_submit_after(cmd, cmds[0]);

		/* nothing else to do, so drop the context already */
		_cmd_data_context_free(ctx);
	} else {
		/* error */
		_cmd_data_error(ctx, reply);
	}
}

static void _cmd_bdat_cb(const struct smtp_reply *reply,
	      void *context)
{
	struct _cmd_data_context *ctx = (struct _cmd_data_context *)context;

	/* got BDAT reply, so there must be ones pending */
	i_assert(array_count(&ctx->cmds) > 0);

	if ((reply->status / 100) != 2) {
		/* error */
		_cmd_data_error(ctx, reply);
		return;
	}

	/* drop the command from the list */
	array_pop_front(&ctx->cmds);

	/* send more BDAT commands if necessary */
	(void)_cmd_bdat_send_chunks(ctx, NULL);

	if (array_count(&ctx->cmds) == 0) {
		/* all of the BDAT commands finished already */
		_cmd_data_context_free(ctx);
	}
}

static void _cmd_bdat_sent_cb(void *context)
{
	struct _cmd_data_context *ctx = (struct _cmd_data_context *)context;

	/* send more BDAT commands if possible */
	(void)_cmd_bdat_send_chunks(ctx, NULL);
}

static int
_cmd_bdat_read_data(struct _cmd_data_context *ctx, size_t *data_size_r)
{
	int ret;

	while ((ret=i_stream_read(ctx->data)) > 0);

	if (ret < 0) {
		if (ret != -2 && ctx->data->stream_errno != 0) {
			e_error(ctx->cmd_data->event,
				"Failed to read DATA stream: %s",
				i_stream_get_error(ctx->data));
			smtp_client_command_fail(&ctx->cmd_data,
				SMTP_CLIENT_COMMAND_ERROR_BROKEN_PAYLOAD,
				"Broken payload stream");
			return -1;
		}
	}

	*data_size_r = i_stream_get_data_size(ctx->data);
	return 0;
}

static void
_cmd_bdat_send_chunks(struct _cmd_data_context *ctx,
	struct smtp_client_command *after)
{
	struct smtp_client_connection *conn = ctx->conn;
	const struct smtp_client_settings *set = &conn->set;
	struct smtp_client_command *const *cmds, *cmd, *cmd_prev;
	unsigned int count;
	struct istream *chunk;
	size_t data_size, max_chunk_size;

	if (smtp_client_command_get_state(ctx->cmd_data) >=
		SMTP_CLIENT_COMMAND_STATE_SUBMITTED) {
		/* finished or aborted */
		return;
	}

	/* pipeline management: determine where to submit the next command */
	cmds = array_get(&ctx->cmds, &count);
	cmd_prev = NULL;
	if (after != NULL) {
		i_assert(count == 0);
		cmd_prev = after;
	} else if (count > 0) {
		cmd_prev = cmds[count-1];
		smtp_client_command_unlock(cmd_prev);
	}

	data_size = ctx->data_left;
	if (data_size > 0) {
		max_chunk_size = set->max_data_chunk_size;
	} else {
		if (ctx->data->v_offset < ctx->data_offset) {
			/* previous BDAT command not completely sent */
			return;
		}
		max_chunk_size = i_stream_get_max_buffer_size(ctx->data);
		if (set->max_data_chunk_size < max_chunk_size)
			max_chunk_size = set->max_data_chunk_size;
		if (_cmd_bdat_read_data(ctx, &data_size) < 0)
			return;
	}

	/* Keep sending more chunks until pipeline is filled to the limit */
	cmd = NULL;
	while (data_size > max_chunk_size ||
		(data_size == max_chunk_size && !ctx->data->eof)) {
		size_t size = (data_size > set->max_data_chunk_size ?
			set->max_data_chunk_size : data_size);
		chunk = i_stream_create_range(ctx->data,
			ctx->data_offset, size);

		cmd = smtp_client_command_new(conn,
			ctx->cmd_data->flags |
				SMTP_CLIENT_COMMAND_FLAG_PIPELINE,
			_cmd_bdat_cb, ctx);
		smtp_client_command_set_abort_callback(cmd,
			_cmd_data_abort_cb, ctx);
		smtp_client_command_set_stream(cmd, chunk, FALSE);
		i_stream_unref(&chunk);
		smtp_client_command_printf(cmd,
			"BDAT %"PRIuUOFF_T, (uoff_t)size);
		smtp_client_command_submit_after(cmd, cmd_prev);
		array_push_back(&ctx->cmds, &cmd);

		ctx->data_offset += size;
		data_size -= size;

		if (array_count(&ctx->cmds) >= set->max_data_chunk_pipeline) {
			/* pipeline full */
			if (ctx->data_left != 0) {
				/* data stream size known:
				   record where we left off */
				ctx->data_left = data_size;
			}
			smtp_client_command_lock(cmd);
			return;
		}

		cmd_prev = cmd;
	}

	if (ctx->data_left != 0) {
		/* data stream size known:
		record where we left off */
		ctx->data_left = data_size;
	} else if (!ctx->data->eof) {
		/* more to read */
		if (cmd != NULL) {
			smtp_client_command_set_sent_callback(cmd,
				_cmd_bdat_sent_cb, ctx);
		}
		return;
	}

	/* the last chunk, which may actually be empty */
	chunk = i_stream_create_range(ctx->data,
		ctx->data_offset, data_size);

	/* submit final command */
	cmd = ctx->cmd_data;
	smtp_client_command_set_stream(cmd, chunk, FALSE);
	i_stream_unref(&chunk);
	smtp_client_command_printf(cmd,
		"BDAT %"PRIuSIZE_T" LAST", data_size);
	smtp_client_command_submit_after(cmd, cmd_prev);

	if (array_count(&ctx->cmds) == 0) {
		/* all of the previous BDAT commands got replies already */
		_cmd_data_context_free(ctx);
	}
}

#undef smtp_client_command_data_submit_after
struct smtp_client_command *
smtp_client_command_data_submit_after(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct smtp_client_command *after,
	struct istream *data,
	smtp_client_command_callback_t *callback,
	void *context)
{
	const struct smtp_client_settings *set = &conn->set;
	struct _cmd_data_context *ctx;
	struct smtp_client_command *cmd, *cmd_data;

	/* create the final command early for reference by the caller;
	   it will not be submitted for now. The DATA command is handled in 
	   two stages (== command submissions), the BDAT command in one or more. */
	cmd = cmd_data = smtp_client_command_create(conn,
		flags, callback, context);

	/* protect against race conditions */
	cmd_data->delay_failure = TRUE;

	/* create context in the final command's pool */
	ctx = p_new(cmd->pool, struct _cmd_data_context, 1);
	ctx->conn = conn;
	ctx->pool = cmd->pool;
	ctx->cmd_data = cmd;

	/* capture abort event with our context */
	smtp_client_command_set_abort_callback(cmd, _cmd_data_abort_cb, ctx);

	if ((conn->caps.standard & SMTP_CAPABILITY_CHUNKING) == 0) {
		/* DATA */
		ctx->data = data;
		i_stream_ref(data);

		p_array_init(&ctx->cmds, ctx->pool, 1);

		/* Data stream is sent in one go in the second stage. Since the data
		   is sent in a '<CRLF>.<CRLF>'-terminated stream, it size is not
		   relevant here. */
		smtp_client_command_set_stream(cmd, ctx->data, TRUE);

		/* Submit the initial DATA command */
		cmd = smtp_client_command_new(conn, flags, _cmd_data_cb, ctx);
		smtp_client_command_set_abort_callback(cmd,
			_cmd_data_abort_cb, ctx);
		smtp_client_command_write(cmd, "DATA");
		smtp_client_command_submit_after(cmd, after);
		array_push_back(&ctx->cmds, &cmd);

	} else {
		/* BDAT */
		ctx->data = data = i_stream_create_crlf(data);

		p_array_init(&ctx->cmds, ctx->pool,
			conn->set.max_data_chunk_pipeline);

		/* The data stream is sent in multiple chunks. Either the size of the
		   data stream is known or it is not. These cases are handled a little
		   differently. */
		if (i_stream_get_size(data, TRUE, &ctx->data_left) > 0) {
			/* size is known */
			i_assert(ctx->data_left >= data->v_offset);
			ctx->data_left -= data->v_offset;
		} else {
			/* size is unknown */
			ctx->data_left = 0;

			/* Make sure we can send chunks of sufficient size by
			   making the data stream buffer size limit at least
			   equally large. */
			if (i_stream_get_max_buffer_size(ctx->data) <
				set->max_data_chunk_size) {
				i_stream_set_max_buffer_size(
					ctx->data, set->max_data_chunk_size);
			}
		}

		/* Send the first BDAT command(s) */
		ctx->data_offset = data->v_offset;
		_cmd_bdat_send_chunks(ctx, after);
	}

	cmd_data->delay_failure = FALSE;
	return cmd_data;
}

#undef smtp_client_command_data_submit
struct smtp_client_command *
smtp_client_command_data_submit(
	struct smtp_client_connection *conn,
	enum smtp_client_command_flags flags,
	struct istream *data,
	smtp_client_command_callback_t *callback, void *context)
{
	return smtp_client_command_data_submit_after
		(conn, flags, NULL, data, callback, context);
}
