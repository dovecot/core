/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "smtp-reply.h"

#include "smtp-server-private.h"

/*
 * Logging
 */

static inline void ATTR_FORMAT(2, 3)
smtp_server_reply_debug(struct smtp_server_reply *reply,
			const char *format, ...)
{
	struct smtp_server_command *command = reply->command;
	struct smtp_server_connection *conn = command->context.conn;
	const struct smtp_server_settings *set = &conn->set;
	va_list args;

	if (set->debug) {
		va_start(args, format);
		if (command->replies_expected > 1) {
			i_debug("%s-server: conn %s: "
				"command %s; %u reply [%u/%u]: %s",
				smtp_protocol_name(set->protocol),
				smtp_server_connection_label(conn),
				smtp_server_command_label(command),
				reply->content->status,
				reply->index+1, command->replies_expected,
				t_strdup_vprintf(format, args));
		} else {
			i_debug("%s-server: conn %s: "
				"command %s; %u reply: %s",
				smtp_protocol_name(set->protocol),
				smtp_server_connection_label(conn),
				smtp_server_command_label(command),
				reply->content->status,
				t_strdup_vprintf(format, args));
		}
		va_end(args);
	}
}

/*
 * Reply
 */

static void smtp_server_reply_destroy(struct smtp_server_reply *reply)
{
	if (reply->command == NULL)
		return;

	smtp_server_reply_debug(reply, "Destroy");

	if (reply->content == NULL)
		return;
	str_free(&reply->content->text);
}

static void smtp_server_reply_clear(struct smtp_server_reply *reply)
{
	smtp_server_reply_destroy(reply);
	if (reply->submitted) {
		i_assert(reply->command->replies_submitted > 0);
		reply->command->replies_submitted--;
	}
	reply->submitted = FALSE;
	reply->forwarded = FALSE;
}

static struct smtp_server_reply *
smtp_server_reply_alloc(struct smtp_server_command *cmd, unsigned int index)
{
	struct smtp_server_reply *reply;
	pool_t pool = cmd->context.pool;

	if (array_is_created(&cmd->replies)) {
		reply = array_idx_modifiable(&cmd->replies, index);
		/* get rid of any existing reply */
		i_assert(!reply->sent);
		smtp_server_reply_clear(reply);
	} else {
		p_array_init(&cmd->replies, pool, cmd->replies_expected);
		array_idx_clear(&cmd->replies, cmd->replies_expected - 1);
		reply = array_idx_modifiable(&cmd->replies, index);
	}
	return reply;
}

struct smtp_server_reply *
smtp_server_reply_create_index(struct smtp_server_command *cmd,
			       unsigned int index, unsigned int status,
			       const char *enh_code)
{
	struct smtp_server_reply *reply;
	pool_t pool = cmd->context.pool;

	i_assert(cmd->replies_expected > 0);
	i_assert(index < cmd->replies_expected);

	/* RFC 5321, Section 4.2:

	   In the absence of extensions negotiated with the client, SMTP servers
	   MUST NOT send reply codes whose first digits are other than 2, 3, 4,
	   or 5.  Clients that receive such out-of-range codes SHOULD normally
	   treat them as fatal errors and terminate the mail transaction.
	 */
	i_assert(status >= 200 && status < 560);

	/* RFC 2034, Section 4:

	   All status codes returned by the server must agree with the primary
	   response code, that is, a 2xx response must incorporate a 2.X.X code,
	   a 4xx response must incorporate a 4.X.X code, and a 5xx response must
	   incorporate a 5.X.X code.
	 */
	i_assert(enh_code == NULL || *enh_code == '\0' ||
		((unsigned int)(enh_code[0] - '0') == (status / 100)
			&& enh_code[1] == '.'));

	reply = smtp_server_reply_alloc(cmd, index);
	reply->index = index;
	reply->command = cmd;

	if (reply->content == NULL)
		reply->content = p_new(pool, struct smtp_server_reply_content, 1);
	reply->content->status = status;
	if (enh_code == NULL || *enh_code == '\0') {
		reply->content->status_prefix =
			p_strdup_printf(pool, "%03u-", status);
	} else {
		reply->content->status_prefix =
			p_strdup_printf(pool, "%03u-%s ", status, enh_code);
	}
	reply->content->text = str_new(default_pool, 256);
	return reply;
}

struct smtp_server_reply *
smtp_server_reply_create(struct smtp_server_command *cmd,
			 unsigned int status, const char *enh_code)
{
	return smtp_server_reply_create_index(cmd, 0, status, enh_code);
}

struct smtp_server_reply *
smtp_server_reply_create_forward(struct smtp_server_command *cmd,
	unsigned int index, const struct smtp_reply *from)
{
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create_index(cmd, index,
		from->status, smtp_reply_get_enh_code(from));
	smtp_reply_write(reply->content->text, from);
	reply->forwarded = TRUE;

	return reply;
}

void smtp_server_reply_free(struct smtp_server_command *cmd)
{
	unsigned int i;

	if (!array_is_created(&cmd->replies))
		return;

	for (i = 0; i < cmd->replies_expected; i++) {
		struct smtp_server_reply *reply =
			array_idx_modifiable(&cmd->replies, i);
		smtp_server_reply_destroy(reply);
	}
}

void smtp_server_reply_add_text(struct smtp_server_reply *reply,
				const char *text)
{
	string_t *textbuf = reply->content->text;

	i_assert(!reply->submitted);

	if (*text == '\0')
		return;

	do {
		const char *p;

		reply->content->last_line = str_len(textbuf);

		p = strchr(text, '\n');
		str_append(textbuf, reply->content->status_prefix);
		if (p == NULL) {
			str_append(textbuf, text);
			text = NULL;
		} else {
			if (p > text && *(p-1) == '\r')
				str_append_data(textbuf, text, p - text - 1);
			else
				str_append_data(textbuf, text, p - text);
			text = p + 1;
		}
		str_append(textbuf, "\r\n");
	} while (text != NULL && *text != '\0');
}

void smtp_server_reply_submit(struct smtp_server_reply *reply)
{
	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	i_assert(str_len(reply->content->text) >= 5);
	smtp_server_reply_debug(reply, "Submitted");

	reply->command->replies_submitted++;
	reply->submitted = TRUE;
	smtp_server_command_submit_reply(reply->command);
}

void smtp_server_reply_submit_duplicate(struct smtp_server_cmd_ctx *_cmd,
					unsigned int index,
					unsigned int from_index)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply, *from_reply;

	i_assert(cmd->replies_expected > 0);
	i_assert(index < cmd->replies_expected);
	i_assert(from_index < cmd->replies_expected);
	i_assert(array_is_created(&cmd->replies));

	from_reply = array_idx_modifiable(&cmd->replies, from_index);
	i_assert(from_reply->content != NULL);
	i_assert(from_reply->submitted);

	reply = smtp_server_reply_alloc(cmd, index);
	reply->index = index;
	reply->command = cmd;
	reply->content = from_reply->content;

	smtp_server_reply_submit(reply);
}

void smtp_server_reply_indexv(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, va_list args)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create_index(cmd, index, status, enh_code);
	smtp_server_reply_add_text(reply, t_strdup_vprintf(fmt, args));
	smtp_server_reply_submit(reply);
}

void smtp_server_reply(struct smtp_server_cmd_ctx *_cmd,
	unsigned int status, const char *enh_code, const char *fmt, ...)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	va_list args;

	i_assert(cmd->replies_expected <= 1);

	va_start(args, fmt);
	smtp_server_reply_indexv(_cmd, 0, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_index(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	smtp_server_reply_indexv(_cmd, index, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_index_forward(struct smtp_server_cmd_ctx *cmd,
	unsigned int index, const struct smtp_reply *from)
{
	smtp_server_reply_submit(
		smtp_server_reply_create_forward(cmd->cmd, index, from));
}

void smtp_server_reply_forward(struct smtp_server_cmd_ctx *_cmd,
			       const struct smtp_reply *from)
{
	struct smtp_server_command *cmd = _cmd->cmd;

	i_assert(cmd->replies_expected <= 1);

	smtp_server_reply_submit(
		smtp_server_reply_create_forward(cmd, 0, from));
}

static void ATTR_FORMAT(4, 0)
smtp_server_reply_allv(struct smtp_server_cmd_ctx *_cmd,
		       unsigned int status, const char *enh_code,
		       const char *fmt, va_list args)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;
	const char *text;
	unsigned int first, i = 0;

	/* find the first unsent reply */
	if (array_is_created(&cmd->replies)) {
		for (; i < cmd->replies_expected; i++) {
			struct smtp_server_reply *reply =
				array_idx_modifiable(&cmd->replies, i);
			if (!reply->sent)
				break;
		}
		i_assert (i < cmd->replies_expected);
	}
	first = i++;

	/* compose the reply text */
	text = t_strdup_vprintf(fmt, args);

	/* submit the first remaining reply */
	reply = smtp_server_reply_create_index(cmd, first, status, enh_code);
	smtp_server_reply_add_text(reply, text);
	smtp_server_reply_submit(reply);

	/* duplicate the rest from it */
	for (; i < cmd->replies_expected; i++)
		smtp_server_reply_submit_duplicate(_cmd, i, first);
}

void smtp_server_reply_all(struct smtp_server_cmd_ctx *_cmd,
			   unsigned int status, const char *enh_code,
			   const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	smtp_server_reply_allv(_cmd, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_early(struct smtp_server_cmd_ctx *_cmd,
			     unsigned int status, const char *enh_code,
			     const char *fmt, ...)
{
	va_list args;

	_cmd->cmd->reply_early = TRUE;

	va_start(args, fmt);
	smtp_server_reply_allv(_cmd, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_quit(struct smtp_server_cmd_ctx *_cmd)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create(cmd, 221, "2.0.0");
	smtp_server_reply_add_text(reply, "Bye");
	smtp_server_reply_submit(reply);
}

const char *smtp_server_reply_get_one_line(struct smtp_server_reply *reply)
{
	string_t *textbuf, *str;
	const char *text, *p;
	size_t text_len, prefix_len, line_len;

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;
	i_assert(str_len(textbuf) > 0);

	prefix_len = strlen(reply->content->status_prefix);
	str = t_str_new(256);
	text = str_c(textbuf);
	text_len = str_len(textbuf);

	for (;;) {
		p = strchr(text, '\n');
		i_assert(p != NULL && p > text && *(p-1) == '\r');
		str_append_data(str, text, p - text - 1);
		line_len = (size_t)(p - text) + 1;
		i_assert(text_len >= line_len);
		text_len -= line_len;
		text = p + 1;

		if (text_len <= prefix_len)
			break;

		text_len -= prefix_len;
		text += prefix_len;
		str_append_c(str, ' ');
	}

	return str_c(str);
}

static int smtp_server_reply_send_real(struct smtp_server_reply *reply)
{
	struct smtp_server_command *cmd = reply->command;
	struct smtp_server_connection *conn = cmd->context.conn;
	const struct smtp_server_settings *set = &conn->set;
	struct ostream *output = conn->conn.output;
	string_t *textbuf;
	char *text;
	int ret = 0;

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;
	i_assert(str_len(textbuf) > 0);

	/* substitute '-' with ' ' in last line */
	text = str_c_modifiable(textbuf);
	text = text + reply->content->last_line + 3;
	if (text[0] != ' ') {
		i_assert(text[0] == '-');
		text[0] = ' ';
	}

	if (o_stream_send(output, str_data(textbuf), str_len(textbuf)) < 0) {
		smtp_server_connection_handle_output_error(conn);
		return -1;
	}

	if (set->debug) {
		smtp_server_reply_debug(reply, "Sent: %s",
			smtp_server_reply_get_one_line(reply));
	}
	return ret;
}

int smtp_server_reply_send(struct smtp_server_reply *reply)
{
	int ret;

	if (reply->sent)
		return 0;

	T_BEGIN {
		ret = smtp_server_reply_send_real(reply);
	} T_END;

	reply->sent = TRUE;
	return ret;
}

/*
 * EHLO reply
 */

struct smtp_server_reply *
smtp_server_reply_create_ehlo(struct smtp_server_command *cmd)
{
	struct smtp_server_connection *conn = cmd->context.conn;
	struct smtp_server_reply *reply;
	string_t *textbuf;

	reply = smtp_server_reply_create(cmd, 250, "");
	textbuf = reply->content->text;
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, conn->set.hostname);
	str_append(textbuf, "\r\n");

	return reply;
}

void smtp_server_reply_ehlo_add(struct smtp_server_reply *reply,
				const char *keyword)
{
	string_t *textbuf;

	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	reply->content->last_line = str_len(textbuf);
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, keyword);
	str_append(textbuf, "\r\n");
}

void smtp_server_reply_ehlo_add_param(struct smtp_server_reply *reply,
	const char *keyword, const char *param_fmt, ...)
{
	va_list args;
	string_t *textbuf;

	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	reply->content->last_line = str_len(textbuf);
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, keyword);
	if (*param_fmt != '\0') {
		va_start(args, param_fmt);
		str_append_c(textbuf, ' ');
		str_vprintfa(textbuf, param_fmt, args);
		va_end(args);
	}
	str_append(textbuf, "\r\n");
}

void smtp_server_reply_ehlo_add_xclient(struct smtp_server_reply *reply)
{
	static const char *base_fields =
		"ADDR PORT PROTO HELO LOGIN TTL TIMEOUT";
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;

	if (!smtp_server_connection_is_trusted(conn))
		return;
	if (conn->set.xclient_extensions == NULL ||
	    *conn->set.xclient_extensions == NULL) {
		smtp_server_reply_ehlo_add_param(reply, "XCLIENT", "%s",
			base_fields);
		return;
	}

	smtp_server_reply_ehlo_add_param(reply, "XCLIENT", "%s",
		t_strconcat(base_fields, " ",
			t_strarray_join(conn->set.xclient_extensions, " "),
			NULL));
}
