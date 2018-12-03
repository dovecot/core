/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "str-sanitize.h"
#include "mail-user.h"
#include "iostream-ssl.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "smtp-client-command.h"

#include "submission-recipient.h"
#include "submission-backend-relay.h"

struct submission_backend_relay {
	struct submission_backend backend;

	struct smtp_client_connection *conn;
	struct smtp_client_transaction *trans;

	bool xclient_sent:1;
	bool trans_started:1;
	bool trusted:1;
};

static struct submission_backend_vfuncs backend_relay_vfuncs;

/*
 * Common
 */

/* The command handling of the submission relay service aims to follow the
   following rules:

   - Attempt to keep pipelined commands pipelined when relaying them to the
     actual relay service.
   - Don't forward commands if they're known to fail at the relay server. Errors
     can still occur if pipelined commands fail. Abort subsequent pending
     commands if such failures affect those commands.
   - Keep predictable errors consistent as much as possible; send our own reply
     if the error condition is clear (e.g. missing MAIL, RCPT).
*/

static bool
backend_relay_handle_relay_reply(struct submission_backend_relay *backend,
				 struct smtp_server_cmd_ctx *cmd,
				 const struct smtp_reply *reply,
				 struct smtp_reply *reply_r)
{
	const char *enh_code, *msg, *log_msg = NULL;
	const char *const *reply_lines;
	bool result = TRUE;

	*reply_r = *reply;

	switch (reply->status) {
	case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
		enh_code = "4.4.0";
		msg = "Failed to connect to relay server";
		result = FALSE;
		break;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
		enh_code = smtp_reply_get_enh_code(reply);
		log_msg = "Lost connection to relay server";
		reply_lines = smtp_reply_get_text_lines_omit_prefix(reply);
		msg = t_strconcat("Lost connection to relay server:\n",
				  t_strarray_join(reply_lines, "\n"), NULL);
		result = FALSE;
		break;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
	case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
	case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
		enh_code = "4.4.0";
		log_msg = msg = "Lost connection to relay server";
		result = FALSE;
		break;
	/* RFC 4954, Section 6: 530 5.7.0 Authentication required

	   This response SHOULD be returned by any command other than AUTH,
	   EHLO, HELO, NOOP, RSET, or QUIT when server policy requires
	   authentication in order to perform the requested action and
	   authentication is not currently in force. */
	case 530:
		log_msg = "Relay server requires authentication";
		enh_code = "4.3.5",
		msg = "Internal error occurred. "
		      "Refer to server log for more information.";
		result = FALSE;
		break;
	default:
		break;
	}

	if (!result) {
		const char *detail = "", *reason;

		i_assert(msg != NULL);

		switch (reply->status) {
		case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
			i_unreached();
		case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
			detail = " (DNS lookup)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
		case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
			detail = " (connect)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
		case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
			detail = " (connection lost)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
			detail = " (bad reply)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
			detail = " (timed out)";
			break;
		default:
			break;
		}

		reason = t_strdup_printf("%s%s", msg, detail);
		smtp_client_transaction_destroy(&backend->trans);
		if (log_msg != NULL)
			i_error("%s: %s", log_msg, smtp_reply_log(reply));
		submission_backend_fail(&backend->backend, cmd,
					enh_code, reason);
		return FALSE;
	}

	if (!smtp_reply_has_enhanced_code(reply)) {
		reply_r->enhanced_code =
			SMTP_REPLY_ENH_CODE(reply->status / 100, 0, 0);
	}
	return TRUE;
}

/*
 * Mail transaction
 */

static void
backend_relay_trans_finished(struct submission_backend_relay *backend)
{
	backend->trans = NULL;
}

static void
backend_relay_trans_start_callback(
	const struct smtp_reply *relay_reply ATTR_UNUSED,
	struct submission_backend_relay *backend ATTR_UNUSED)
{
	/* nothing to do */
}

static void
backend_relay_trans_start(struct submission_backend *_backend,
			  struct smtp_server_transaction *trans ATTR_UNUSED,
			  const struct smtp_address *path,
			  const struct smtp_params_mail *params)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	if (backend->trans == NULL) {
		backend->trans_started = TRUE;
		backend->trans = smtp_client_transaction_create(
			backend->conn, path, params, 0,
			backend_relay_trans_finished, backend);
		smtp_client_transaction_set_immediate(backend->trans, TRUE);
		smtp_client_transaction_start(
			backend->trans, backend_relay_trans_start_callback,
			backend);
	} else if (!backend->trans_started) {
		backend->trans_started = TRUE;
		smtp_client_transaction_start_empty(
			backend->trans, path, params,
			backend_relay_trans_start_callback, backend);
	}
}

static void
backend_relay_trans_free(struct submission_backend *_backend,
			 struct smtp_server_transaction *trans ATTR_UNUSED)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	backend->trans_started = FALSE;

	if (backend->trans == NULL)
		return;

	smtp_client_transaction_destroy(&backend->trans);
}

struct smtp_client_transaction *
submission_backend_relay_init_transaction(
	struct submission_backend_relay *backend,
	enum smtp_client_transaction_flags flags)
{
	i_assert(backend->trans == NULL);

	backend->trans = smtp_client_transaction_create_empty(
		backend->conn, flags,
		backend_relay_trans_finished, backend);
	smtp_client_transaction_set_immediate(backend->trans, TRUE);

	return backend->trans;
}

/*
 * EHLO, HELO commands
 */

struct relay_cmd_helo_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_helo *data;

	struct smtp_client_command *cmd_relayed;
};

static void
relay_cmd_helo_update_xclient(struct submission_backend_relay *backend,
			      struct smtp_server_cmd_helo *data)
{
	struct smtp_proxy_data proxy_data;

	if (!backend->trusted)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = data->helo.domain;
	proxy_data.proto = (data->helo.old_smtp ?
		SMTP_PROXY_PROTOCOL_SMTP : SMTP_PROXY_PROTOCOL_ESMTP);
	smtp_client_connection_update_proxy_data(backend->conn, &proxy_data);

	smtp_client_connection_send_xclient(backend->conn);
	backend->xclient_sent = TRUE;
}

static void
relay_cmd_helo_reply(struct smtp_server_cmd_ctx *cmd,
		     struct relay_cmd_helo_context *helo)
{
	struct submission_backend_relay *backend = helo->backend;

	/* relay an XCLIENT command */
	if (helo->data->changed)
		relay_cmd_helo_update_xclient(backend, helo->data);

	T_BEGIN {
		submission_backend_helo_reply_submit(&backend->backend, cmd,
						     helo->data);
	} T_END;
}

static void
relay_cmd_helo_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_helo_context *helo)
{
	struct smtp_server_cmd_ctx *cmd = helo->cmd;
	struct submission_backend_relay *backend = helo->backend;
	struct smtp_reply reply;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(&reply)) {
		relay_cmd_helo_reply(cmd, helo);
	} else {
		/* RFC 2034, Section 4:

		   These codes must appear in all 2xx, 4xx, and 5xx response
		   lines other than initial greeting and any response to HELO
		   or EHLO.
		 */
		reply.enhanced_code = SMTP_REPLY_ENH_CODE_NONE;
		smtp_server_reply_forward(cmd, &reply);
	}
}

static void
relay_cmd_helo_start(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		     struct relay_cmd_helo_context *helo)
{
	struct submission_backend_relay *backend = helo->backend;

	/* relay an XCLIENT command */
	if (helo->data->changed)
		relay_cmd_helo_update_xclient(backend, helo->data);
}

static int
backend_relay_cmd_helo(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd,
		       struct smtp_server_cmd_helo *data)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_helo_context *helo;

	helo = p_new(cmd->pool, struct relay_cmd_helo_context, 1);
	helo->backend = backend;
	helo->cmd = cmd;
	helo->data = data;

	/* this is not the first HELO/EHLO; just relay a RSET command */
	smtp_server_command_add_hook(
		cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
		relay_cmd_helo_start, helo);
	helo->cmd_relayed = smtp_client_command_rset_submit
		(backend->conn, 0, relay_cmd_helo_callback, helo);
	return 0;
}

/*
 * MAIL command
 */

struct relay_cmd_mail_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_mail *data;

	struct smtp_client_transaction_mail *relay_mail;
};

static void
relay_cmd_mail_update_xclient(struct submission_backend_relay *backend)
{
	struct client *client = backend->backend.client;
	struct smtp_proxy_data proxy_data;
	struct smtp_server_helo_data *helo_data =
		smtp_server_connection_get_helo_data(client->conn);

	if (backend->xclient_sent)
		return;
	if (!backend->trusted)
		return;
	if (helo_data->domain == NULL)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = helo_data->domain;
	proxy_data.proto = SMTP_PROXY_PROTOCOL_ESMTP;
	smtp_client_connection_update_proxy_data(backend->conn, &proxy_data);
	
	smtp_client_connection_send_xclient(backend->conn);
	backend->xclient_sent = TRUE;
}


static void
relay_cmd_mail_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_mail_context *mail_cmd)
{
	if (mail_cmd->relay_mail != NULL)
		smtp_client_transaction_mail_abort(&mail_cmd->relay_mail);
}

static void
relay_cmd_mail_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_mail_context *mail_cmd)
{
	struct smtp_server_cmd_ctx *cmd = mail_cmd->cmd;
	struct submission_backend_relay *backend = mail_cmd->backend;
	struct smtp_reply reply;

	/* finished relaying MAIL command to relay server */
	i_assert(mail_cmd != NULL);
	mail_cmd->relay_mail = NULL;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(relay_reply)) {
		/* if relay accepts it, we accept it too */

		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(relay_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 0);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

static int
relay_cmd_mail_parameter_auth(struct submission_backend_relay *backend,
			      struct smtp_server_cmd_ctx *cmd,
			      enum smtp_capability relay_caps,
			      struct smtp_server_cmd_mail *data)
{
	struct client *client = backend->backend.client;
	struct smtp_params_mail *params = &data->params;
	struct smtp_address *auth_addr;
	const char *error;

	if ((relay_caps & SMTP_CAPABILITY_AUTH) == 0)
		return 0;

	auth_addr = NULL;
	if (smtp_address_parse_username(cmd->pool, client->user->username,
					&auth_addr, &error) < 0) {
		i_warning("Username `%s' is not a valid SMTP address: %s",
			  client->user->username, error);
	}

	params->auth = auth_addr;
	return 0;
}

static int
relay_cmd_mail_parameter_size(struct submission_backend_relay *backend,
			      struct smtp_server_cmd_ctx *cmd,
			      enum smtp_capability relay_caps,
			      struct smtp_server_cmd_mail *data)
{
	struct client *client = backend->backend.client;
	uoff_t max_size;

	/* SIZE=<size-value>: RFC 1870 */

	if (data->params.size == 0 || (relay_caps & SMTP_CAPABILITY_SIZE) == 0)
		return 0;

	/* determine actual size limit (account for our additions) */
	max_size = client_get_max_mail_size(client);
	if (max_size > 0 && data->params.size > max_size) {
		smtp_server_reply(cmd, 552, "5.3.4",
			"Message size exceeds fixed maximum message size");
		return -1;
	}

	/* relay the SIZE parameter (account for additional size) */
	data->params.size += SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE;
	return 0;
}

static int
backend_relay_cmd_mail(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd,
		       struct smtp_server_cmd_mail *data)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	enum smtp_capability relay_caps =
		smtp_client_connection_get_capabilities(backend->conn);
	struct relay_cmd_mail_context *mail_cmd;

	/* check and adjust parameters where necessary */
	if (relay_cmd_mail_parameter_auth(backend, cmd, relay_caps, data) < 0)
		return -1;
	if (relay_cmd_mail_parameter_size(backend, cmd, relay_caps, data) < 0)
		return -1;

	relay_cmd_mail_update_xclient(backend);

	/* queue command (pipeline) */
	mail_cmd = p_new(cmd->pool, struct relay_cmd_mail_context, 1);
	mail_cmd->backend = backend;
	mail_cmd->cmd = cmd;
	mail_cmd->data = data;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     relay_cmd_mail_replied, mail_cmd);

	if (backend->trans == NULL) {
		/* start client transaction */
		backend->trans_started = TRUE;
		backend->trans = smtp_client_transaction_create(
			backend->conn, data->path, &data->params, 0,
			backend_relay_trans_finished, backend);
		smtp_client_transaction_set_immediate(backend->trans, TRUE);
		smtp_client_transaction_start(backend->trans,
					      relay_cmd_mail_callback, mail_cmd);
	} else {
		/* forward pipelined MAIL command */
		i_assert(backend->trans_started);
		mail_cmd->relay_mail = smtp_client_transaction_add_mail(
			backend->trans, data->path, &data->params,
			relay_cmd_mail_callback, mail_cmd);
	}
	return 0;
}

/*
 * RCPT command
 */

struct relay_cmd_rcpt_context {
	struct submission_backend_relay *backend;
	struct submission_recipient *rcpt;

	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_transaction_rcpt *relay_rcpt;
};

static void
relay_cmd_rcpt_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_rcpt_context *rcpt_cmd)
{
	if (rcpt_cmd->relay_rcpt != NULL)
		smtp_client_transaction_rcpt_abort(&rcpt_cmd->relay_rcpt);
}

static void
relay_cmd_rcpt_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_rcpt_context *rcpt_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rcpt_cmd->cmd;
	struct submission_backend_relay *backend = rcpt_cmd->backend;
	struct submission_recipient *rcpt = rcpt_cmd->rcpt;
	struct smtp_client_transaction_rcpt *relay_rcpt = rcpt_cmd->relay_rcpt;
	struct smtp_reply reply;

	/* finished relaying RCPT command to relay server */
	i_assert(rcpt_cmd != NULL);
	rcpt_cmd->relay_rcpt = NULL;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(&reply)) {
		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(&reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 5);

		i_assert(relay_rcpt != NULL);
		rcpt->backend_context = relay_rcpt;
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

static int
backend_relay_cmd_rcpt(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd,
		       struct submission_recipient *srcpt)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct smtp_server_recipient *rcpt = srcpt->rcpt;
	struct relay_cmd_rcpt_context *rcpt_cmd;

	/* queue command (pipeline) */
	rcpt_cmd = p_new(cmd->pool, struct relay_cmd_rcpt_context, 1);
	rcpt_cmd->backend = backend;
	rcpt_cmd->cmd = cmd;
	rcpt_cmd->rcpt = srcpt;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     relay_cmd_rcpt_replied, rcpt_cmd);

	if (backend->trans == NULL)
		(void)submission_backend_relay_init_transaction(backend, 0);
	rcpt_cmd->relay_rcpt = smtp_client_transaction_add_pool_rcpt(
		backend->trans, rcpt->pool, rcpt->path, &rcpt->params,
		relay_cmd_rcpt_callback, rcpt_cmd);
	return 0;
}

/*
 * RSET command
 */

struct relay_cmd_rset_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_relayed;
};

static void
relay_cmd_rset_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_rset_context *rset_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rset_cmd->cmd;
	struct submission_backend_relay *backend = rset_cmd->backend;
	struct smtp_reply reply;

	/* finished relaying MAIL command to relay server */
	i_assert(rset_cmd != NULL);
	rset_cmd->cmd_relayed = NULL;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

static int
backend_relay_cmd_rset(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_rset_context *rset_cmd;

	rset_cmd = p_new(cmd->pool, struct relay_cmd_rset_context, 1);
	rset_cmd->backend = backend;
	rset_cmd->cmd = cmd;

	if (backend->trans != NULL) {
		/* RSET pipelined after MAIL */
		smtp_client_transaction_reset(backend->trans,
					      relay_cmd_rset_callback,
					      rset_cmd);
	} else {
		/* RSET alone */
		rset_cmd->cmd_relayed = smtp_client_command_rset_submit(
			backend->conn, 0, relay_cmd_rset_callback, rset_cmd);
	}
	return 0;
}

/*
 * DATA/BDAT commands
 */

struct relay_cmd_data_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_transaction *trans;
};

static void
relay_cmd_data_rcpt_callback(const struct smtp_reply *relay_reply,
			     struct submission_recipient *srcpt)
{
	struct smtp_server_recipient *rcpt = srcpt->rcpt;
	struct smtp_server_cmd_ctx *cmd = rcpt->cmd;
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)srcpt->backend;
	struct client *client = srcpt->backend->client;
	struct smtp_server_transaction *trans =
		smtp_server_connection_get_transaction(client->conn);
	struct smtp_reply reply;

	i_assert(HAS_ALL_BITS(trans->flags,
			      SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT));

	/* check for fatal problems */
	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(&reply)) {
		i_info("Successfully relayed message: "
		       "from=<%s>, to=<%s>, size=%"PRIuUOFF_T", "
		       "id=%s, rcpt=%u/%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       smtp_address_encode(rcpt->path),
		       client->state.data_size, trans->id,
		       rcpt->index, array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(&reply), 128));

	} else {
		i_info("Failed to relay message: "
		       "from=<%s>, to=<%s>, size=%"PRIuUOFF_T", "
		       "rcpt=%u/%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       smtp_address_encode(rcpt->path),
		       client->state.data_size, rcpt->index,
		       array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(&reply), 128));
	}

	smtp_server_reply_index_forward(cmd, rcpt->index, &reply);
}

static void
relay_cmd_data_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_data_context *data_ctx)
{
	struct smtp_server_cmd_ctx *cmd = data_ctx->cmd;
	struct smtp_server_transaction *trans = data_ctx->trans;
	struct submission_backend_relay *backend = data_ctx->backend;
	struct client *client = backend->backend.client;
	struct smtp_reply reply;

	/* finished relaying message to relay server */

	if (HAS_ALL_BITS(trans->flags,
			 SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT)) {
		/* handled recipient replies individually */
		return;
	}

	/* check for fatal problems */
	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(&reply)) {
		i_info("Successfully relayed message: "
		       "from=<%s>, size=%"PRIuUOFF_T", "
		       "id=%s, nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, trans->id,
		       array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(&reply), 128));

	} else {
		i_info("Failed to relay message: "
		       "from=<%s>, size=%"PRIuUOFF_T", nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(&reply), 128));
	}

	smtp_server_reply_forward(cmd, &reply);
}

static void
backend_relay_cmd_data_init_callbacks(struct submission_backend_relay *backend,
				      struct smtp_server_transaction *trans)
{
	struct client *client = backend->backend.client;
	struct submission_recipient *const *rcptp;

	if (!HAS_ALL_BITS(trans->flags,
			  SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT))
		return;

	array_foreach_modifiable(&client->rcpt_to, rcptp) {
		struct submission_recipient *rcpt = *rcptp;
		struct smtp_client_transaction_rcpt *relay_rcpt =
			rcpt->backend_context;

		smtp_client_transaction_rcpt_set_data_callback(
			relay_rcpt, relay_cmd_data_rcpt_callback, rcpt);
	}
}

static int
backend_relay_cmd_data(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd,
		       struct smtp_server_transaction *trans,
		       struct istream *data_input, uoff_t data_size ATTR_UNUSED)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_data_context *data_ctx;

	/* start relaying to relay server */
	data_ctx = p_new(trans->pool, struct relay_cmd_data_context, 1);
	data_ctx->backend = backend;
	data_ctx->cmd = cmd;
	data_ctx->trans = trans;
	trans->context = (void*)data_ctx;

	i_assert(backend->trans != NULL);

	backend_relay_cmd_data_init_callbacks(backend, trans);

	smtp_client_transaction_send(backend->trans, data_input,
				     relay_cmd_data_callback, data_ctx);
	return 0;
}

/*
 * VRFY command
 */

struct relay_cmd_vrfy_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_relayed;
};

static void
relay_cmd_vrfy_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_vrfy_context *vrfy_cmd)
{
	struct smtp_server_cmd_ctx *cmd = vrfy_cmd->cmd;
	struct submission_backend_relay *backend = vrfy_cmd->backend;
	struct smtp_reply reply;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	/* RFC 5321, Section 3.5.3:

	   A server MUST NOT return a 250 code in response to a VRFY or EXPN
	   command unless it has actually verified the address. In particular,
	   a server MUST NOT return 250 if all it has done is to verify that the
	   syntax given is valid. In that case, 502 (Command not implemented)
	   or 500 (Syntax error, command unrecognized) SHOULD be returned. As
	   stated elsewhere, implementation (in the sense of actually validating
	   addresses and returning information) of VRFY and EXPN are strongly
	   recommended. Hence, implementations that return 500 or 502 for VRFY
	   are not in full compliance with this specification.
	 */
	if (reply.status == 500 || reply.status == 502) {
		smtp_server_cmd_vrfy_reply_default(cmd);
		return;
	}

	if (!smtp_reply_has_enhanced_code(&reply)) {
		switch (relay_reply->status) {
		case 250:
		case 251:
		case 252:
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 5, 0);
			break;
		default:
			break;
		}
	}

	smtp_server_reply_forward(cmd, &reply);
}

static int
backend_relay_cmd_vrfy(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd, const char *param)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_vrfy_context *vrfy_cmd;

	vrfy_cmd = p_new(cmd->pool, struct relay_cmd_vrfy_context, 1);
	vrfy_cmd->backend = backend;
	vrfy_cmd->cmd = cmd;

	vrfy_cmd->cmd_relayed = smtp_client_command_vrfy_submit(
		backend->conn, 0, param, relay_cmd_vrfy_callback, vrfy_cmd);
	return 0;
}

/*
 * NOOP command
 */

struct relay_cmd_noop_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_relayed;
};

static void
relay_cmd_noop_callback(const struct smtp_reply *relay_reply,
			struct relay_cmd_noop_context *noop_cmd)
{
	struct smtp_server_cmd_ctx *cmd = noop_cmd->cmd;
	struct submission_backend_relay *backend = noop_cmd->backend;
	struct smtp_reply reply;

	if (!backend_relay_handle_relay_reply(backend, cmd, relay_reply,
					      &reply))
		return;

	if (smtp_reply_is_success(&reply))
		smtp_server_cmd_noop_reply_success(cmd);
	else
		smtp_server_reply_forward(cmd, &reply);
}

static int
backend_relay_cmd_noop(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_noop_context *noop_cmd;

	noop_cmd = p_new(cmd->pool, struct relay_cmd_noop_context, 1);
	noop_cmd->backend = backend;
	noop_cmd->cmd = cmd;

	noop_cmd->cmd_relayed = smtp_client_command_noop_submit(
		backend->conn, 0, relay_cmd_noop_callback, noop_cmd);
	return 0;
}

/*
 * QUIT command
 */

struct relay_cmd_quit_context {
	struct submission_backend_relay *backend;

	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_relayed;
};

static void
relay_cmd_quit_destroy(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_quit_context *quit_cmd)
{
	if (quit_cmd->cmd_relayed != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_relayed);
}

static void
relay_cmd_quit_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		       struct relay_cmd_quit_context *quit_cmd)
{
	if (quit_cmd->cmd_relayed != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_relayed);
}

static void relay_cmd_quit_finish(struct relay_cmd_quit_context *quit_cmd)
{
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	if (quit_cmd->cmd_relayed != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_relayed);
	smtp_server_reply_quit(cmd);
}

static void
relay_cmd_quit_callback(const struct smtp_reply *relay_reply ATTR_UNUSED,
			struct relay_cmd_quit_context *quit_cmd)
{
	quit_cmd->cmd_relayed = NULL;
	relay_cmd_quit_finish(quit_cmd);
}

static void relay_cmd_quit_relay(struct relay_cmd_quit_context *quit_cmd)
{
	struct submission_backend_relay *backend = quit_cmd->backend;
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	if (quit_cmd->cmd_relayed != NULL)
		return;

	if (smtp_client_connection_get_state(backend->conn)
		< SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* Don't bother relaying QUIT command when relay is not
		   fully initialized. */
		smtp_server_reply_quit(cmd);
		return;
	}

	/* RFC 5321, Section 4.1.1.10:

	   The sender MUST NOT intentionally close the transmission channel
	   until it sends a QUIT command, and it SHOULD wait until it receives
	   the reply (even if there was an error response to a previous
	   command). */
	quit_cmd->cmd_relayed =
		smtp_client_command_new(backend->conn, 0,
					relay_cmd_quit_callback, quit_cmd);
	smtp_client_command_write(quit_cmd->cmd_relayed, "QUIT");
	smtp_client_command_submit(quit_cmd->cmd_relayed);
}

static void
relay_cmd_quit_next(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		    struct relay_cmd_quit_context *quit_cmd)
{
	/* QUIT command is next to reply */
	relay_cmd_quit_relay(quit_cmd);
}

static int
backend_relay_cmd_quit(struct submission_backend *_backend,
		       struct smtp_server_cmd_ctx *cmd)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;
	struct relay_cmd_quit_context *quit_cmd;

	quit_cmd = p_new(cmd->pool, struct relay_cmd_quit_context, 1);
	quit_cmd->backend = backend;
	quit_cmd->cmd = cmd;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     relay_cmd_quit_next, quit_cmd);
	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     relay_cmd_quit_replied, quit_cmd);
	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     relay_cmd_quit_destroy, quit_cmd);

	if (smtp_client_connection_get_state(backend->conn)
		>= SMTP_CLIENT_CONNECTION_STATE_READY)
		relay_cmd_quit_relay(quit_cmd);
	return 0;
}

/*
 * Relay backend
 */

struct submission_backend_relay *
submission_backend_relay_create(
	struct client *client,
	const struct submision_backend_relay_settings *set)
{
	struct submission_backend_relay *backend;
	struct mail_user *user = client->user;
	struct ssl_iostream_settings ssl_set;
	struct smtp_client_settings smtp_set;
	pool_t pool;

	pool = pool_alloconly_create("submission relay backend", 1024);
	backend = p_new(pool, struct submission_backend_relay, 1);
	submission_backend_init(&backend->backend, pool, client,
				&backend_relay_vfuncs);

	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(user, &ssl_set);
	if (set->ssl_verify)
		ssl_set.verbose_invalid_cert = TRUE;
	else
		ssl_set.allow_invalid_cert = TRUE;

	/* make relay connection */
	i_zero(&smtp_set);
	smtp_set.my_hostname = set->my_hostname;
	smtp_set.extra_capabilities = set->extra_capabilities;
	smtp_set.ssl = &ssl_set;
	smtp_set.debug = user->mail_debug;

	if (set->rawlog_dir != NULL) {
		smtp_set.rawlog_dir =
			mail_user_home_expand(user, set->rawlog_dir);
	}

	if (set->trusted) {
		struct smtp_server_helo_data *helo_data =
			smtp_server_connection_get_helo_data(client->conn);

		backend->trusted = TRUE;
		smtp_set.peer_trusted = TRUE;

		smtp_set.proxy_data.helo = helo_data->domain;
		smtp_set.proxy_data.proto = SMTP_PROXY_PROTOCOL_ESMTP;

		if (user->conn.remote_ip != NULL) {
			smtp_set.proxy_data.source_ip =
				*user->conn.remote_ip;
			smtp_set.proxy_data.source_port =
				user->conn.remote_port;
		}
		smtp_set.proxy_data.login = user->username;
	}

	smtp_set.username = set->user;
	smtp_set.master_user = set->master_user;
	smtp_set.password = set->password;
	smtp_set.connect_timeout_msecs = set->connect_timeout_msecs;
	smtp_set.command_timeout_msecs = set->command_timeout_msecs;

	if (set->path == NULL) {
		backend->conn = smtp_client_connection_create(
			smtp_client, set->protocol, set->host, set->port,
			set->ssl_mode, &smtp_set);
	} else {
		backend->conn = smtp_client_connection_create_unix(
			smtp_client, set->protocol, set->path, &smtp_set);
	}

	return backend;
}

struct submission_backend *
submission_backend_relay_get(struct submission_backend_relay *backend)
{
	return &backend->backend;
}

struct smtp_client_connection *
submission_backend_relay_get_connection(
	struct submission_backend_relay *backend)
{
	return backend->conn;
}

struct smtp_client_transaction *
submission_backend_relay_get_transaction(
	struct submission_backend_relay *backend)
{
	return backend->trans;
}

static void backend_relay_destroy(struct submission_backend *_backend)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	if (backend->trans != NULL)
		smtp_client_transaction_destroy(&backend->trans);
	if (backend->conn != NULL)
		smtp_client_connection_close(&backend->conn);
}

static void backend_relay_ready_cb(const struct smtp_reply *reply,
				   void *context)
{
	struct submission_backend_relay *backend = context;

	/* check relay status */
	if (!smtp_reply_is_success(reply)) {
		i_error("Failed to establish relay connection: %s",
			smtp_reply_log(reply));
		submission_backend_fail(&backend->backend, NULL,
			"4.4.0", "Failed to establish relay connection");
		return;
	}

	/* notify the backend API about the fact that we're ready and propagate
	   our capabilities */
	submission_backend_started(&backend->backend,
		smtp_client_connection_get_capabilities(backend->conn));
}

static void backend_relay_start(struct submission_backend *_backend)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	smtp_client_connection_connect(backend->conn,
				       backend_relay_ready_cb, backend);
}

/* try to proxy pipelined commands in a similarly pipelined fashion */
static void
backend_relay_client_input_pre(struct submission_backend *_backend)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	if (backend->conn != NULL)
		smtp_client_connection_cork(backend->conn);
}
static void
backend_relay_client_input_post(struct submission_backend *_backend)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	if (backend->conn != NULL)
		smtp_client_connection_uncork(backend->conn);
}

static uoff_t
backend_relay_get_max_mail_size(struct submission_backend *_backend)
{
	struct submission_backend_relay *backend =
		(struct submission_backend_relay *)_backend;

	return smtp_client_connection_get_size_capability(backend->conn);
}

static struct submission_backend_vfuncs backend_relay_vfuncs = {
	.destroy = backend_relay_destroy,

	.start = backend_relay_start,

	.client_input_pre = backend_relay_client_input_pre,
	.client_input_post = backend_relay_client_input_post,

	.get_max_mail_size = backend_relay_get_max_mail_size,

	.trans_start = backend_relay_trans_start,
	.trans_free = backend_relay_trans_free,

	.cmd_helo = backend_relay_cmd_helo,

	.cmd_mail = backend_relay_cmd_mail,
	.cmd_rcpt = backend_relay_cmd_rcpt,
	.cmd_rset = backend_relay_cmd_rset,
	.cmd_data = backend_relay_cmd_data,

	.cmd_vrfy = backend_relay_cmd_vrfy,
	.cmd_noop = backend_relay_cmd_noop,

	.cmd_quit = backend_relay_cmd_quit,
};

