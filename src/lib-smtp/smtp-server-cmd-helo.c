/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "smtp-syntax.h"

#include "smtp-server-private.h"

/* EHLO, HELO commands */

static void
cmd_helo_completed(struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_helo *data)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure */
		return;
	}

	if (conn->pending_helo == &data->helo)
		conn->pending_helo = NULL;

	/* success */
	smtp_server_connection_reset_state(conn);

	i_free(conn->helo_domain);
	conn->helo_domain = i_strdup(data->helo.domain);
	conn->helo.domain = conn->helo_domain;
	conn->helo.domain_valid = data->helo.domain_valid;
	conn->helo.old_smtp = data->helo.old_smtp;
}

static void
cmd_helo_next(struct smtp_server_cmd_ctx *cmd,
	      struct smtp_server_cmd_helo *data)
{
	struct smtp_server_connection *conn = cmd->conn;

	if (conn->helo.domain == NULL ||
		strcmp(conn->helo.domain, data->helo.domain) != 0 ||
		conn->helo.old_smtp != data->helo.old_smtp)
		data->changed = TRUE; /* definitive assessment */
}

static void
smtp_server_cmd_helo_run(struct smtp_server_cmd_ctx *cmd, const char *params,
			 bool old_smtp)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_cmd_helo *helo_data;
	struct smtp_server_command *command = cmd->cmd;
	bool first = (conn->pending_helo == NULL && conn->helo.domain == NULL);
	const char *domain = NULL;
	int ret;

	/* parse domain argument */

	if (*params == '\0') {
		smtp_server_reply(cmd, 501, "", "Missing hostname");
		return;
	}
	ret = smtp_helo_domain_parse(params, !old_smtp, &domain);

	smtp_server_command_input_lock(cmd);
	if (conn->state.state == SMTP_SERVER_STATE_GREETING)
		smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_HELO);

	helo_data = p_new(cmd->pool, struct smtp_server_cmd_helo, 1);
	helo_data->helo.domain = p_strdup(cmd->pool, domain);
	helo_data->helo.domain_valid = ( ret >= 0 );
	helo_data->helo.old_smtp = old_smtp;
	helo_data->first = first;
	command->data = helo_data;

	if (conn->helo.domain == NULL ||
	    (domain != NULL && strcmp(conn->helo.domain, domain) != 0) ||
	    conn->helo.old_smtp != old_smtp)
		helo_data->changed = TRUE; /* preliminary assessment */

	if (conn->pending_helo == NULL)
		conn->pending_helo = &helo_data->helo;

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_helo_next, helo_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_helo_completed, helo_data);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_helo != NULL) {
		/* specific implementation of EHLO command */
		if ((ret=callbacks->conn_cmd_helo(conn->context,
			cmd, helo_data)) <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}

	if (!smtp_server_command_is_replied(command)) {
		/* submit default EHLO reply if none is provided */
		smtp_server_cmd_ehlo_reply_default(cmd);
	}
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_ehlo(struct smtp_server_cmd_ctx *cmd,
			 const char *params)
{
	/* ehlo = "EHLO" SP ( Domain / address-literal ) CRLF */

	smtp_server_cmd_helo_run(cmd, params, FALSE);
}

void smtp_server_cmd_helo(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	/* helo = "HELO" SP Domain CRLF */

	smtp_server_cmd_helo_run(cmd, params, TRUE);
}

struct smtp_server_reply *
smtp_server_cmd_ehlo_reply_create(struct smtp_server_cmd_ctx *cmd)
{
	static struct {
		const char *name;
		void (*add)(struct smtp_server_reply *reply);
	} standard_caps[] = {
		/* Sorted alphabetically */
		{ "8BITMIME", smtp_server_reply_ehlo_add_8bitmime },
		{ "BINARYMIME", smtp_server_reply_ehlo_add_binarymime },
		{ "CHUNKING", smtp_server_reply_ehlo_add_chunking },
		{ "DSN", smtp_server_reply_ehlo_add_dsn },
		{ "ENHANCEDSTATUSCODES",
		  smtp_server_reply_ehlo_add_enhancedstatuscodes },
		{ "PIPELINING", smtp_server_reply_ehlo_add_pipelining },
		{ "SIZE", smtp_server_reply_ehlo_add_size },
		{ "STARTTLS", smtp_server_reply_ehlo_add_starttls },
		{ "VRFY", smtp_server_reply_ehlo_add_vrfy },
		{ "XCLIENT", smtp_server_reply_ehlo_add_xclient }
	};
	const unsigned int standard_caps_count = N_ELEMENTS(standard_caps);
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_cmd_helo *helo_data = command->data;
	const struct smtp_capability_extra *extra_caps = NULL;
	unsigned int extra_caps_count, i, j;
	struct smtp_server_reply *reply;

	i_assert(cmd->cmd->reg->func == smtp_server_cmd_ehlo);
	reply = smtp_server_reply_create_ehlo(cmd->cmd);

	if (helo_data->helo.old_smtp)
		return reply;

	extra_caps_count = 0;
	if (array_is_created(&conn->extra_capabilities)) {
		extra_caps = array_get(&conn->extra_capabilities,
				       &extra_caps_count);
	}

	i = j = 0;
	while (i < standard_caps_count || j < extra_caps_count) {
		if (i < standard_caps_count && 
		    (j >= extra_caps_count ||
		     strcasecmp(standard_caps[i].name,
				extra_caps[j].name) < 0)) {
			standard_caps[i].add(reply);
			i++;
		} else {
			smtp_server_reply_ehlo_add_params(
				reply, extra_caps[j].name,
				extra_caps[j].params);
			j++;
		}
	}
	return reply;
}

void smtp_server_cmd_ehlo_reply_default(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_reply *reply;

	reply = smtp_server_cmd_ehlo_reply_create(cmd);
	smtp_server_reply_submit(reply);
}
