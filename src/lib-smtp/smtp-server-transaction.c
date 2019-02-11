/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strfuncs.h"
#include "guid.h"
#include "base64.h"
#include "message-date.h"
#include "smtp-address.h"
#include "smtp-params.h"

#include "smtp-server-private.h"

static void
smtp_server_transaction_update_event(struct smtp_server_transaction *trans)
{
	struct smtp_server_connection *conn = trans->conn;
	struct event *event = trans->event;

	event_add_str(event, "transaction_id", trans->id);
	event_add_str(event, "mail_from",
		      smtp_address_encode(trans->mail_from));
	smtp_params_mail_add_to_event(&trans->params, conn->set.capabilities,
				      event);
	event_set_append_log_prefix(event,
				    t_strdup_printf("trans %s: ", trans->id));
}

struct smtp_server_transaction *
smtp_server_transaction_create(struct smtp_server_connection *conn,
			       enum smtp_server_transaction_flags flags,
			       const struct smtp_address *mail_from,
			       const struct smtp_params_mail *params,
			       const struct timeval *timestamp)
{
	struct smtp_server_transaction *trans;
	pool_t pool;
	guid_128_t guid;
	string_t *id;

	/* create new transaction */
	pool = pool_alloconly_create("smtp server transaction", 4096);
	trans = p_new(pool, struct smtp_server_transaction, 1);
	trans->pool = pool;
	trans->conn = conn;

	/* generate transaction ID */
	id = t_str_new(30);
	guid_128_generate(guid);
	base64_encode(guid, sizeof(guid), id);
	i_assert(str_c(id)[str_len(id)-2] == '=');
	str_truncate(id, str_len(id)-2); /* drop trailing "==" */
	trans->id = p_strdup(pool, str_c(id));

	trans->flags = flags;
	trans->mail_from = smtp_address_clone(trans->pool, mail_from);
	smtp_params_mail_copy(pool, &trans->params, params);
	trans->timestamp = *timestamp;

	trans->event = event_create(conn->event);
	smtp_server_transaction_update_event(trans);

	if (conn->callbacks != NULL &&
	    conn->callbacks->conn_trans_start != NULL)
		conn->callbacks->conn_trans_start(conn->context, trans);

	return trans;
}

void smtp_server_transaction_free(struct smtp_server_transaction **_trans)
{
	struct smtp_server_transaction *trans = *_trans;
	struct smtp_server_connection *conn = trans->conn;
	struct smtp_server_recipient **rcptp;

	if (conn->callbacks != NULL &&
	    conn->callbacks->conn_trans_free != NULL)
		conn->callbacks->conn_trans_free(conn->context, trans);

	if (array_is_created(&trans->rcpt_to)) {
		array_foreach_modifiable(&trans->rcpt_to, rcptp)
			smtp_server_recipient_destroy(rcptp);
	}

	event_unref(&trans->event);
	pool_unref(&trans->pool);
	*_trans = NULL;
}

struct smtp_server_recipient *
smtp_server_transaction_find_rcpt_duplicate(
	struct smtp_server_transaction *trans,
	struct smtp_server_recipient *rcpt)
{
	struct smtp_server_recipient *const *rcptp;

	i_assert(array_is_created(&trans->rcpt_to));
	array_foreach(&trans->rcpt_to, rcptp) {
		struct smtp_server_recipient *drcpt = *rcptp;

		if (drcpt == rcpt)
			continue;
		if (smtp_address_equals(drcpt->path, rcpt->path) &&
		    smtp_params_rcpt_equals(&drcpt->params, &rcpt->params))
			return drcpt;
	}
	return NULL;
}

void smtp_server_transaction_add_rcpt(struct smtp_server_transaction *trans,
				      struct smtp_server_recipient *rcpt)
{
	if (!array_is_created(&trans->rcpt_to))
		p_array_init(&trans->rcpt_to, trans->pool, 8);

	rcpt->trans = trans;
	rcpt->index = array_count(&trans->rcpt_to);

	array_push_back(&trans->rcpt_to, &rcpt);
}

bool smtp_server_transaction_has_rcpt(struct smtp_server_transaction *trans)
{
	return (array_is_created(&trans->rcpt_to) &&
		array_count(&trans->rcpt_to) > 0);
}

unsigned int
smtp_server_transaction_rcpt_count(struct smtp_server_transaction *trans)
{
	if (!array_is_created(&trans->rcpt_to))
		return 0;
	return array_count(&trans->rcpt_to);
}

void smtp_server_transaction_last_data(struct smtp_server_transaction *trans,
				       struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_recipient *const *rcptp;

	trans->cmd = cmd;

	i_assert(array_is_created(&trans->rcpt_to));
	array_foreach(&trans->rcpt_to, rcptp)
		smtp_server_recipient_last_data(*rcptp, cmd);
}

void smtp_server_transaction_fail_data(struct smtp_server_transaction *trans,
	struct smtp_server_cmd_ctx *data_cmd,
	unsigned int status, const char *enh_code,
	const char *fmt, va_list args)
{
	struct smtp_server_recipient *const *rcpts;
	const char *msg;
	unsigned int count, i;

	msg = t_strdup_vprintf(fmt, args);
	rcpts = array_get(&trans->rcpt_to, &count);
	for (i = 0; i < count; i++) {
		smtp_server_reply_index(data_cmd, i,
			status, enh_code, "<%s> %s",
			smtp_address_encode(rcpts[i]->path), msg);
	}
}

void smtp_server_transaction_write_trace_record(string_t *str,
	struct smtp_server_transaction *trans)
{
	struct smtp_server_connection *conn = trans->conn;
	const struct smtp_server_helo_data *helo_data = &conn->helo;
	const char *host, *secstr, *rcpt_to = NULL;

	if (array_count(&trans->rcpt_to) == 1) {
		struct smtp_server_recipient *const *rcpts =
			array_front(&trans->rcpt_to);

		rcpt_to = smtp_address_encode(rcpts[0]->path);
	}

	/* from */
	str_append(str, "Received: from ");
	if (helo_data->domain_valid)
		str_append(str, helo_data->domain);
	else
		str_append(str, "unknown");
	host = "";
	if (conn->conn.remote_ip.family != 0)
		host = net_ip2addr(&conn->conn.remote_ip);
	if (host[0] != '\0') {
		str_append(str, " ([");
		str_append(str, host);
		str_append(str, "])");
	}
	/* (using) */
	secstr = smtp_server_connection_get_security_string(conn);
	if (secstr != NULL) {
		str_append(str, "\r\n\t(using ");
		str_append(str, secstr);
		str_append(str, ")");
	}
	/* by, with */
	str_append(str, "\r\n\tby ");
	str_append(str, conn->set.hostname);
	str_append(str, " with ");
	str_append(str, smtp_server_connection_get_protocol_name(conn));
	/* id */
	str_append(str, "\r\n\tid ");
	str_append(str, trans->id);
	/* (envelope-from) */
	str_append(str, "\r\n\t(envelope-from <");
	smtp_address_write(str, trans->mail_from);
	str_append(str, ">)");
	/* for */
	if (rcpt_to != NULL) {
		str_append(str, "\r\n\tfor <");
		str_append(str, rcpt_to);
		str_append(str, ">");
	}
	str_append(str, "; ");
	/* date */
	str_append(str, message_date_create(trans->timestamp.tv_sec));
	str_printfa(str, "\r\n");
}
