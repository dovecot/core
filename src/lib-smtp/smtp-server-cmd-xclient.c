/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "smtp-syntax.h"
#include "smtp-reply.h"

#include "smtp-server-private.h"

/* XCLIENT command (http://www.postfix.org/XCLIENT_README.html) */

static bool
cmd_xclient_check_state(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;

	/* http://www.postfix.org/XCLIENT_README.html:

	   The XCLIENT command may be sent at any time, except in the middle
	   of a mail delivery transaction (i.e. between MAIL and DOT, or MAIL
	   and RSET). */
	if (conn->state.trans != NULL) {
		smtp_server_reply(cmd, 503, "5.5.0",
			"XCLIENT not permitted during a mail transaction");
		return FALSE;
	}
	return TRUE;
}

static void
cmd_xclient_completed(struct smtp_server_cmd_ctx *cmd,
		      struct smtp_proxy_data *proxy_data)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure */
		return;
	}

	/* success */
	smtp_server_connection_reset_state(conn);
	smtp_server_connection_set_proxy_data(conn, proxy_data);
}

static void
cmd_xclient_recheck(struct smtp_server_cmd_ctx *cmd,
		    struct smtp_proxy_data *proxy_data ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;

	/* all preceeding commands have finished and now the transaction state is
	   clear. This provides the opportunity to re-check the protocol state */
	if (!cmd_xclient_check_state(cmd))
		return;
	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_XCLIENT);

	/* succes; send greeting */
	smtp_server_reply(cmd, 220, NULL, "%s %s",
		conn->set.hostname, conn->set.login_greeting);
	return;
}

static void
smtp_server_cmd_xclient_extra_field(struct smtp_server_connection *conn,
				    pool_t pool, const struct smtp_param *param,
				    ARRAY_TYPE(smtp_proxy_data_field) *fields)
{
	struct smtp_proxy_data_field *field;

	if (conn->set.xclient_extensions == NULL ||
	    !str_array_icase_find(conn->set.xclient_extensions, param->keyword))
		return;

	if (!array_is_created(fields))
		p_array_init(fields, pool, 8);
	field = array_append_space(fields);
	field->name = p_strdup(pool, param->keyword);
	field->value = p_strdup(pool, param->value);
}

void smtp_server_cmd_xclient(struct smtp_server_cmd_ctx *cmd,
			     const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_proxy_data *proxy_data;
	ARRAY_TYPE(smtp_proxy_data_field) extra_fields = ARRAY_INIT;
	const char *const *argv;

	/* xclient-command = XCLIENT 1*( SP attribute-name"="attribute-value )
	   attribute-name = ( NAME | ADDR | PORT | PROTO | HELO | LOGIN )
	   attribute-value = xtext
	 */

	if ((conn->set.capabilities & SMTP_CAPABILITY_XCLIENT) == 0) {
		smtp_server_reply(cmd,
			502, "5.5.1", "Unsupported command");
		return;
	}

	/* check transaction state as far as possible */
	if (!cmd_xclient_check_state(cmd))
		return;

	/* check whether client is trusted */
	if (!smtp_server_connection_is_trusted(conn)) {
		smtp_server_reply(cmd, 550, "5.7.14",
			"You are not from trusted IP");
		return;
	}

	proxy_data = p_new(cmd->pool, struct smtp_proxy_data, 1);

	argv = t_strsplit(params, " ");
	for (; *argv != NULL; argv++) {
		struct smtp_param param;
		const char *error;

		if (smtp_param_parse(pool_datastack_create(), *argv,
			&param, &error) < 0) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"Invalid parameter: %s", error);
			return;
		}

		param.keyword = t_str_ucase(param.keyword);

		if (smtp_xtext_parse(param.value, &param.value, &error) < 0) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"Invalid %s parameter: %s",
				param.keyword, error);
			return;
		}

		if (strcmp(param.keyword, "ADDR") == 0) {
			bool ipv6 = FALSE;
			if (strcasecmp(param.value, "[UNAVAILABLE]") == 0)
				continue;
			if (strncasecmp(param.value, "IPV6:", 5) == 0) {
				ipv6 = TRUE;
				param.value += 5;
			}
			if (net_addr2ip(param.value, &proxy_data->source_ip) < 0 ||
				(ipv6 && proxy_data->source_ip.family != AF_INET6)) {
				smtp_server_reply(cmd, 501, "5.5.4",
					"Invalid ADDR parameter");
				return;
			}
		} else if (strcmp(param.keyword, "HELO") == 0) {
			if (strcasecmp(param.value, "[UNAVAILABLE]") == 0)
				continue;
			if (smtp_helo_domain_parse
				(param.value, TRUE, &proxy_data->helo) >= 0)
				proxy_data->helo =
					p_strdup(cmd->pool, proxy_data->helo);
		} else if (strcmp(param.keyword, "LOGIN") == 0) {
			if (strcasecmp(param.value, "[UNAVAILABLE]") == 0)
				continue;
			proxy_data->login = p_strdup(cmd->pool, param.value);
		} else if (strcmp(param.keyword, "PORT") == 0) {
			if (strcasecmp(param.value, "[UNAVAILABLE]") == 0)
				continue;
			if (net_str2port(param.value, &proxy_data->source_port) < 0) {
				smtp_server_reply(cmd, 501, "5.5.4",
					"Invalid PORT parameter");
				return;
			}
		} else if (strcmp(param.keyword, "PROTO") == 0) {
			param.value = t_str_ucase(param.value);
			if (strcmp(param.value, "SMTP") == 0)
				proxy_data->proto = SMTP_PROXY_PROTOCOL_SMTP;
			else if (strcmp(param.value, "ESMTP") == 0)
				proxy_data->proto = SMTP_PROXY_PROTOCOL_ESMTP;
			else if (strcmp(param.value, "LMTP") == 0)
				proxy_data->proto = SMTP_PROXY_PROTOCOL_LMTP;
			else {
				smtp_server_reply(cmd, 501, "5.5.4",
					"Invalid PROTO parameter");
				return;
			}
		} else if (strcmp(param.keyword, "TIMEOUT") == 0) {
			if (str_to_uint(param.value,
				&proxy_data->timeout_secs) < 0) {
				smtp_server_reply(cmd, 501, "5.5.4",
					"Invalid TIMEOUT parameter");
				return;
			}
		} else if (strcmp(param.keyword, "TTL") == 0) {
			if (str_to_uint(param.value,
				&proxy_data->ttl_plus_1) < 0) {
				smtp_server_reply(cmd, 501, "5.5.4",
					"Invalid TTL parameter");
				return;
			}
			proxy_data->ttl_plus_1++;
		} else {
			smtp_server_cmd_xclient_extra_field(conn,
				cmd->pool, &param, &extra_fields);
		}
	}

	if (array_is_created(&extra_fields)) {
		proxy_data->extra_fields = array_get(&extra_fields,
			&proxy_data->extra_fields_count);
	}

	smtp_server_command_input_lock(cmd);

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_xclient_recheck, proxy_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_xclient_completed, proxy_data);

	if (conn->state.state == SMTP_SERVER_STATE_GREETING)
		smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_XCLIENT);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_xclient != NULL) {
		/* specific implementation of XCLIENT command */
		callbacks->conn_cmd_xclient(conn->context, cmd, proxy_data);
	}
	smtp_server_command_unref(&command);
}
