/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dns-lookup.h"

#include "smtp-common.h"
#include "smtp-address.h"
#include "smtp-params.h"
#include "smtp-client-private.h"
#include "smtp-client-command.h"
#include "smtp-client-transaction.h"

#include <ctype.h>

const char *const smtp_client_transaction_state_names[] = {
	"new",
	"mail_from",
	"rcpt_to",
	"data",
	"finished",
	"aborted"
};

static void
smtp_client_transaction_submit_more(struct smtp_client_transaction *trans);
static void
smtp_client_transaction_try_complete(struct smtp_client_transaction *trans);

static void
smtp_client_transaction_send_data(struct smtp_client_transaction *trans);

/*
 * Recipient
 */

static struct smtp_client_transaction_rcpt *
smtp_client_transaction_rcpt_new(
	struct smtp_client_transaction *trans,
	const struct smtp_address *rcpt_to,
	const struct smtp_params_rcpt *rcpt_params)
{
	struct smtp_client_transaction_rcpt *rcpt;
	pool_t pool;

	pool = pool_alloconly_create("smtp transaction rcpt", 512);
	rcpt = p_new(pool, struct smtp_client_transaction_rcpt, 1);
	rcpt->pool = pool;
	rcpt->trans = trans;
	rcpt->rcpt_to = smtp_address_clone(pool, rcpt_to);
	smtp_params_rcpt_copy(pool, &rcpt->rcpt_params, rcpt_params);

	array_append(&trans->rcpts_pending, &rcpt, 1);
	return rcpt;
}

static void
smtp_client_transaction_rcpt_free(
	struct smtp_client_transaction_rcpt **_rcpt)
{
	struct smtp_client_transaction_rcpt *rcpt = *_rcpt;

	*_rcpt = NULL;

	/* recipient failed */
	i_assert(rcpt->pool != NULL);
	pool_unref(&rcpt->pool);
}

static void
smtp_client_transaction_rcpt_drop_pending(
	struct smtp_client_transaction_rcpt *prcpt)
{
	struct smtp_client_transaction *trans = prcpt->trans;
	struct smtp_client_transaction_rcpt *const *rcpts;
	unsigned int count;

	rcpts = array_get(&trans->rcpts_pending, &count);
	i_assert(count > 0);
	i_assert(prcpt == rcpts[0]);
	array_delete(&trans->rcpts_pending, 0, 1);

	if (trans->rcpts_next_send_idx > 0)
		trans->rcpts_next_send_idx--;
}

static void
smtp_client_transaction_rcpt_approved(
	struct smtp_client_transaction_rcpt **_prcpt)
{
	struct smtp_client_transaction_rcpt *prcpt = *_prcpt;
	struct smtp_client_transaction *trans = prcpt->trans;
	struct smtp_client_transaction_rcpt *rcpt;
	pool_t pool;

	/* move to transaction pool */
	pool = trans->pool;
	rcpt = p_new(pool, struct smtp_client_transaction_rcpt, 1);
	rcpt->trans = trans;
	rcpt->rcpt_to = smtp_address_clone(pool, prcpt->rcpt_to);
	smtp_params_rcpt_copy(pool, &rcpt->rcpt_params, &prcpt->rcpt_params);
	rcpt->data_callback = prcpt->data_callback;
	rcpt->context = prcpt->context;

	/* recipient is approved */
	array_append(&trans->rcpts, &rcpt, 1);

	/* not pending anymore */
	smtp_client_transaction_rcpt_drop_pending(prcpt);
	smtp_client_transaction_rcpt_free(&prcpt);

	*_prcpt = rcpt;
}

static void
smtp_client_transaction_rcpt_denied(
	struct smtp_client_transaction_rcpt **_prcpt)
{
	struct smtp_client_transaction_rcpt *prcpt = *_prcpt;

	*_prcpt = NULL;

	/* not pending anymore */
	smtp_client_transaction_rcpt_drop_pending(prcpt);
	smtp_client_transaction_rcpt_free(&prcpt);
}

/*
 * Transaction
 */

static inline void ATTR_FORMAT(2, 3)
smtp_client_transaction_debug(struct smtp_client_transaction *trans,
	const char *format, ...)
{
	struct smtp_client_connection *conn = trans->conn;
	va_list args;

	if (conn->set.debug) {
		va_start(args, format);
		i_debug("%s-client: conn %s: transaction: %s",
			smtp_protocol_name(conn->protocol),
			smpt_client_connection_label(conn),
			t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 *
 */

#undef smtp_client_transaction_create
struct smtp_client_transaction *
smtp_client_transaction_create(struct smtp_client_connection *conn,
	const struct smtp_address *mail_from,
	const struct smtp_params_mail *mail_params,
	unsigned int flags ATTR_UNUSED,
	smtp_client_transaction_callback_t *callback, void *context)
{
	struct smtp_client_transaction *trans;
	pool_t pool;

	pool = pool_alloconly_create("smtp transaction", 4096);
	trans = p_new(pool, struct smtp_client_transaction, 1);
	trans->refcount = 1;
	trans->pool = pool;
	trans->callback = callback;
	trans->context = context;

	trans->mail_from = smtp_address_clone(pool, mail_from);
	smtp_params_mail_copy(pool, &trans->mail_params, mail_params);

	trans->conn = conn;
	smtp_client_connection_ref(conn);

	p_array_init(&trans->rcpts_pending, pool, 16);
	p_array_init(&trans->rcpts, pool, 16);

	smtp_client_transaction_debug(trans, "Created");

	return trans;
}

static void
smtp_client_transaction_finish(struct smtp_client_transaction *trans)
{
	struct smtp_client_connection *conn = trans->conn;

	if (trans->state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED)
		return;

	timeout_remove(&trans->to_finish);

	smtp_client_transaction_debug(trans, "Finished");

	io_loop_time_refresh();
	trans->times.finished = ioloop_timeval;

	i_assert(trans->to_send == NULL);

	trans->state = SMTP_CLIENT_TRANSACTION_STATE_FINISHED;
	i_assert(trans->callback != NULL);
	trans->callback(trans->context);

	if (!trans->submitted_data)
		smtp_client_connection_abort_transaction(conn, trans);

	smtp_client_transaction_unref(&trans);
}

void smtp_client_transaction_abort(struct smtp_client_transaction *trans)
{
	struct smtp_client_connection *conn = trans->conn;
	struct smtp_client_transaction_rcpt **rcpts;
	unsigned int i, count;

	if (trans->failing) {
		smtp_client_transaction_debug(trans, "Abort (already failing)");
		return;
	}

	smtp_client_transaction_debug(trans, "Abort");

	/* clean up */
	i_stream_unref(&trans->data_input);
	timeout_remove(&trans->to_send);
	timeout_remove(&trans->to_finish);

	trans->cmd_last = NULL;

	/* abort any pending commands */
	if (trans->cmd_mail_from != NULL)
		smtp_client_command_abort(&trans->cmd_mail_from);
	rcpts = array_get_modifiable(&trans->rcpts_pending, &count);
	for (i = 0; i < count; i++) {
		if (rcpts[i]->cmd_rcpt_to != NULL &&
			conn->state != SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED)
			smtp_client_command_abort(&rcpts[i]->cmd_rcpt_to);
		smtp_client_transaction_rcpt_free(&rcpts[i]);
	}
	array_clear(&trans->rcpts_pending);
	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED) {
		if (trans->cmd_data != NULL)
			smtp_client_command_abort(&trans->cmd_data);
		if (trans->cmd_plug != NULL)
			smtp_client_command_abort(&trans->cmd_plug);
	}
	trans->cmd_data = NULL;
	trans->cmd_plug = NULL;

	smtp_client_connection_abort_transaction(conn, trans);

	/* abort if not finished */
	if (trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED) {
		smtp_client_transaction_debug(trans, "Aborted");

		trans->state = SMTP_CLIENT_TRANSACTION_STATE_ABORTED;
		i_assert(trans->callback != NULL);
		trans->callback(trans->context);

		smtp_client_transaction_unref(&trans);
	}
}

void smtp_client_transaction_ref(struct smtp_client_transaction *trans)
{
	trans->refcount++;
}

void smtp_client_transaction_unref(struct smtp_client_transaction **_trans)
{
	struct smtp_client_transaction *trans = *_trans;
	struct smtp_client_connection *conn = trans->conn;

	*_trans = NULL;

	i_assert(trans->refcount > 0);
	if (--trans->refcount > 0)
		return;

	smtp_client_transaction_debug(trans, "Destroy");

	i_stream_unref(&trans->data_input);
	smtp_client_transaction_abort(trans);

	i_assert(trans->state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED);
	pool_unref(&trans->pool);

	smtp_client_connection_unref(&conn);
}

void smtp_client_transaction_destroy(struct smtp_client_transaction **_trans)
{
	struct smtp_client_transaction *trans = *_trans;
	struct smtp_client_transaction_rcpt **rcpts;
	unsigned int count, i;

	*_trans = NULL;

	smtp_client_transaction_ref(trans);
	smtp_client_transaction_abort(trans);

	/* Make sure this transaction doesn't produce any more callbacks.
	   We cannot fully abort (destroy) these commands, as this may be
	   called from a callback. */
	if (trans->cmd_mail_from != NULL)
		smtp_client_command_drop_callback(trans->cmd_mail_from);
	rcpts = array_get_modifiable(&trans->rcpts_pending, &count);
	for (i = 0; i < count; i++) {
		if (rcpts[i]->cmd_rcpt_to != NULL)
			smtp_client_command_drop_callback(rcpts[i]->cmd_rcpt_to);
	}
	if (trans->cmd_data != NULL)
		smtp_client_command_drop_callback(trans->cmd_data);
	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);

	if (trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED) {
		struct smtp_client_transaction *trans_tmp = trans;

		trans->state = SMTP_CLIENT_TRANSACTION_STATE_ABORTED;
		smtp_client_transaction_unref(&trans_tmp);
	}

	smtp_client_transaction_unref(&trans);
}

void smtp_client_transaction_fail_reply(struct smtp_client_transaction *trans,
	const struct smtp_reply *reply)
{
	struct smtp_client_connection *conn = trans->conn;
	struct smtp_client_transaction_rcpt **rcpts;
	unsigned int i, count;

	if (reply == NULL)
		reply = trans->failure;
	i_assert(reply != NULL);

	trans->failing = TRUE;

	smtp_client_transaction_debug(trans,
		"Returning failure: %s", smtp_reply_log(reply));

	/* hold a reference to prevent early destruction in a callback */
	smtp_client_transaction_ref(trans);

	trans->cmd_last = NULL;

	timeout_remove(&trans->to_send);

	/* MAIL */
	if (trans->cmd_mail_from != NULL) {
		smtp_client_command_abort(&trans->cmd_mail_from);
		if (trans->mail_from_callback != NULL) {
			trans->mail_from_callback(reply,
						  trans->mail_from_context);
		}
	} else if (trans->state == SMTP_CLIENT_TRANSACTION_STATE_PENDING) {
		if (trans->mail_from_callback != NULL) {
			trans->mail_from_callback(reply,
						  trans->mail_from_context);
		}
	}

	/* RCPT */
	rcpts = array_get_modifiable(&trans->rcpts_pending, &count);
	for (i = 0; i < count; i++) {
		struct smtp_client_command *cmd = rcpts[i]->cmd_rcpt_to;

		if (rcpts[i]->failed)
			continue;

		rcpts[i]->cmd_rcpt_to = NULL;
		rcpts[i]->failed = TRUE;

		if (cmd != NULL) {
			smtp_client_command_fail_reply(&cmd, reply);
		} else {
			if (rcpts[i]->rcpt_callback != NULL) {
				rcpts[i]->rcpt_callback(reply,
							rcpts[i]->context);
			}
			rcpts[i]->rcpt_callback = NULL;
		}
	}

	/* DATA */
	if (!trans->data_provided) {
		/* smtp_client_transaction_send() was not called yet
		 */
	} else if (trans->cmd_data != NULL) {
		/* the DATA command is still pending; handle the failure by
		   failing the DATA command. */
		smtp_client_command_fail_reply(&trans->cmd_data, reply);
	} else {
		/* the DATA command was not sent yet; call all DATA callbacks
		   for the recipients that were previously accepted. */
		rcpts = array_get_modifiable(&trans->rcpts, &count);
		for (i = trans->rcpt_next_data_idx; i < count; i++) {
			if (rcpts[i]->data_callback != NULL) {
				rcpts[i]->data_callback(reply,
							rcpts[i]->context);
			}
			rcpts[i]->data_callback = NULL;
		}
		if (trans->data_callback != NULL)
			trans->data_callback(reply, trans->data_context);
		trans->data_callback = NULL;
	}

	/* plug */
	if (trans->failure == NULL)
		trans->failure = smtp_reply_clone(trans->pool, reply);
	if (trans->cmd_plug != NULL &&
		conn->state != SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED)
		smtp_client_command_abort(&trans->cmd_plug);
	trans->cmd_plug = NULL;

	trans->failing = FALSE;

	if (trans->data_provided) {
		/* abort the transaction only if smtp_client_transaction_send()
		   was called (and if it is not aborted already) */
		smtp_client_transaction_abort(trans);
	}

	/* drop reference held earlier in this function */
	smtp_client_transaction_unref(&trans);
}

void smtp_client_transaction_fail(struct smtp_client_transaction *trans,
	unsigned int status, const char *error)
{
	struct smtp_reply reply;

	smtp_reply_init(&reply, status, error);
	smtp_client_transaction_fail_reply(trans, &reply);
}

static void
smtp_client_transaction_timeout(struct smtp_client_transaction *trans)
{
	struct smtp_reply reply;

	smtp_reply_printf(&reply, 451,
		"Remote server not answering "
		"(transaction timed out while %s)",
		smtp_client_transaction_get_state_destription(trans));
	reply.enhanced_code = SMTP_REPLY_ENH_CODE(4, 4, 0);

	smtp_client_transaction_fail_reply(trans, &reply);
}

void smtp_client_transaction_set_timeout(struct smtp_client_transaction *trans,
	unsigned int timeout_msecs)
{
	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);

	trans->finish_timeout_msecs = timeout_msecs;

	if (trans->data_input != NULL && timeout_msecs > 0) {
		/* adjust timeout if it is already started */
		timeout_remove(&trans->to_finish);
		trans->to_finish = timeout_add(trans->finish_timeout_msecs,
			smtp_client_transaction_timeout, trans);
	}
}

static void
smtp_client_transaction_mail_cb(const struct smtp_reply *reply,
				struct smtp_client_transaction *trans)
{
	bool success = smtp_reply_is_success(reply);

	smtp_client_transaction_debug(trans, "Got MAIL reply: %s",
		smtp_reply_log(reply));

	/* plug command line pipeline if no RCPT commands are yet issued */
	if (trans->cmd_mail_from == trans->cmd_last) {
		trans->cmd_plug = trans->cmd_last =
			smtp_client_command_plug(trans->conn, trans->cmd_last);
	}
	trans->cmd_mail_from = NULL;

	if (array_count(&trans->rcpts_pending) > 0)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO;

	if (trans->mail_from_callback != NULL) {
		enum smtp_client_transaction_state state;
		struct smtp_client_transaction *tmp_trans = trans;

		smtp_client_transaction_ref(tmp_trans);
		trans->mail_from_callback(reply, trans->mail_from_context);
		state = trans->state;
		smtp_client_transaction_unref(&tmp_trans);
		if (state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED)
			return;
	}

	if (!success)
		smtp_client_transaction_fail_reply(trans, reply);
}

static void smtp_client_transaction_connection_ready(
	struct smtp_client_transaction *trans)
{
	if (trans->state != SMTP_CLIENT_TRANSACTION_STATE_PENDING)
		return;

	smtp_client_transaction_debug(trans,
		"Connecton is ready for transaction");

	trans->cmd_mail_from = trans->cmd_last =
		smtp_client_command_mail_submit(trans->conn, 0,
			trans->mail_from, &trans->mail_params,
			smtp_client_transaction_mail_cb, trans);
	smtp_client_command_lock(trans->cmd_last);

	trans->state = SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM;

	smtp_client_transaction_submit_more(trans);
}

#undef smtp_client_transaction_start
void smtp_client_transaction_start(
	struct smtp_client_transaction *trans,
	smtp_client_command_callback_t *mail_from_callback, void *context)
{
	struct smtp_client_connection *conn = trans->conn;

	i_assert(trans->state == SMTP_CLIENT_TRANSACTION_STATE_NEW);

	smtp_client_transaction_debug(trans, "Start");

	io_loop_time_refresh();
	trans->times.started = ioloop_timeval;

	trans->mail_from_callback = mail_from_callback;
	trans->mail_from_context = context;

	trans->state = SMTP_CLIENT_TRANSACTION_STATE_PENDING;

	smtp_client_connection_add_transaction(conn, trans);
}

static void
smtp_client_transaction_rcpt_cb(const struct smtp_reply *reply,
				struct smtp_client_transaction_rcpt *rcpt)
{
	struct smtp_client_transaction *trans = rcpt->trans;
	bool success = smtp_reply_is_success(reply);
	smtp_client_command_callback_t *rcpt_callback = rcpt->rcpt_callback;
	void *context = rcpt->context;

	smtp_client_transaction_debug(trans, "Got RCPT reply: %s",
		smtp_reply_log(reply));

	rcpt->failed = !success;
	rcpt->rcpt_callback = NULL;

	/* plug command line pipeline if DATA command is not yet issued */
	if (rcpt->cmd_rcpt_to == trans->cmd_last &&
		trans->cmd_data == NULL) {
		trans->cmd_plug = trans->cmd_last =
			smtp_client_command_plug(trans->conn, trans->cmd_last);
	}
	rcpt->cmd_rcpt_to = NULL;

	if (success)
		smtp_client_transaction_rcpt_approved(&rcpt);
	else
		smtp_client_transaction_rcpt_denied(&rcpt);

	rcpt_callback(reply, context);

	smtp_client_transaction_try_complete(trans);
}

static void
smtp_client_transaction_submit_more(struct smtp_client_transaction *trans)
{
	struct smtp_client_transaction_rcpt *const *rcpt;
	unsigned int count;

	timeout_remove(&trans->to_send);

	if (trans->failure != NULL) {
		smtp_client_transaction_fail_reply(trans, trans->failure);
		return;
	}

	if (trans->state == SMTP_CLIENT_TRANSACTION_STATE_NEW) {
		enum smtp_client_transaction_state state;
		struct smtp_client_transaction *tmp_trans = trans;

		smtp_client_transaction_ref(tmp_trans);
		smtp_client_transaction_start(tmp_trans, NULL, NULL);
		state = trans->state;
		smtp_client_transaction_unref(&tmp_trans);
		if (state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED)
			return;
	}

	if (trans->state <= SMTP_CLIENT_TRANSACTION_STATE_PENDING)
		return;

	rcpt = array_get_modifiable(&trans->rcpts_pending, &count);
	if (trans->rcpts_next_send_idx < count) {
		unsigned int i;

		smtp_client_transaction_debug(trans, "Sending recipients");

		if (trans->cmd_last != NULL)
			smtp_client_command_unlock(trans->cmd_last);

		for (i = trans->rcpts_next_send_idx; i < count; i++) {
			rcpt[i]->cmd_rcpt_to = trans->cmd_last =
				smtp_client_command_rcpt_submit_after(
					trans->conn, 0,	trans->cmd_last,
					rcpt[i]->rcpt_to, &rcpt[i]->rcpt_params,
					smtp_client_transaction_rcpt_cb, rcpt[i]);
		}
		trans->rcpts_next_send_idx = i;

		smtp_client_command_lock(trans->cmd_last);

		if (trans->cmd_plug != NULL) {
			i_assert(trans->cmd_last != trans->cmd_plug);
			smtp_client_command_abort(&trans->cmd_plug);
		}
	}

	if (trans->data_input != NULL)
		smtp_client_transaction_send_data(trans);
}

#undef smtp_client_transaction_add_rcpt
void smtp_client_transaction_add_rcpt(
	struct smtp_client_transaction *trans,
	const struct smtp_address *rcpt_to,
	const struct smtp_params_rcpt *rcpt_params,
	smtp_client_command_callback_t *rcpt_callback,
	smtp_client_command_callback_t *data_callback, void *context)
{
	struct smtp_client_transaction_rcpt *rcpt;

	smtp_client_transaction_debug(trans, "Add recipient");

	i_assert(!trans->data_provided);

	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);

	if (trans->cmd_mail_from == NULL &&
		trans->state == SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO;

	rcpt = smtp_client_transaction_rcpt_new(trans, rcpt_to, rcpt_params);
	rcpt->rcpt_callback = rcpt_callback;
	rcpt->data_callback = data_callback;
	rcpt->context = context;

	if (trans->to_send == NULL &&
		(trans->state > SMTP_CLIENT_TRANSACTION_STATE_PENDING ||
			trans->failure != NULL)) {
		trans->to_send = timeout_add_short(0,
			smtp_client_transaction_submit_more, trans);
	}
}

static void
smtp_client_transaction_data_cb(const struct smtp_reply *reply,
				struct smtp_client_transaction *trans)
{
	struct smtp_client_connection *conn = trans->conn;
	struct smtp_client_transaction_rcpt *const *rcpt;
	unsigned int i, count;

	smtp_client_transaction_ref(trans);

	rcpt = array_get_modifiable(&trans->rcpts, &count);
	if (conn->protocol == SMTP_PROTOCOL_LMTP &&
	    trans->cmd_data != NULL && /* NULL when failed early */
	    trans->rcpt_next_data_idx == 0 && count > 0)
		smtp_client_command_set_replies(trans->cmd_data, count);
	for (i = trans->rcpt_next_data_idx; i < count; i++) {
		trans->rcpt_next_data_idx = i + 1;
		if (rcpt[i]->data_callback != NULL)
			rcpt[i]->data_callback(reply, rcpt[i]->context);
		rcpt[i]->data_callback = NULL;
		if (conn->protocol == SMTP_PROTOCOL_LMTP)
			break;
	}
	if (trans->rcpt_next_data_idx < count) {
		smtp_client_transaction_unref(&trans);
		return;
	}

	trans->cmd_data = NULL;

	if (trans->data_callback != NULL)
		trans->data_callback(reply, trans->data_context);
	trans->data_callback = NULL;

	/* finished */
	smtp_client_transaction_finish(trans);

	smtp_client_transaction_unref(&trans);
}

static void
smtp_client_transaction_send_data(struct smtp_client_transaction *trans)
{
	bool finished = FALSE;

	i_assert(trans->data_input != NULL);

	smtp_client_transaction_debug(trans, "Sending data");

	timeout_remove(&trans->to_send);

	if (trans->failure != NULL) {
		smtp_client_transaction_fail_reply(trans, trans->failure);
		finished = TRUE;
	} else if ((array_count(&trans->rcpts) +
		array_count(&trans->rcpts_pending)) == 0) {
		smtp_client_transaction_debug(trans, "No valid recipients");
		finished = TRUE;
	} else {
		trans->cmd_data = smtp_client_command_data_submit_after(
			trans->conn, 0, trans->cmd_last, trans->data_input,
			smtp_client_transaction_data_cb, trans);
		trans->submitted_data = TRUE;

		i_assert(trans->cmd_last != NULL);
		smtp_client_command_unlock(trans->cmd_last);

		smtp_client_transaction_try_complete(trans);
	}

	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);
	trans->cmd_last = NULL;

	if (finished)
		smtp_client_transaction_finish(trans);

	i_stream_unref(&trans->data_input);
}

#undef smtp_client_transaction_send
void smtp_client_transaction_send(
	struct smtp_client_transaction *trans, struct istream *data_input,
	smtp_client_command_callback_t *data_callback, void *data_context)
{
	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);

	if (array_count(&trans->rcpts_pending) == 0)
		smtp_client_transaction_debug(trans, "Got all RCPT replies");

	smtp_client_transaction_debug(trans, "Send");

	trans->data_provided = TRUE;

	i_assert(trans->data_input == NULL);
	trans->data_input = data_input;
	i_stream_ref(data_input);

	trans->data_callback = data_callback;
	trans->data_context = data_context;

	if (trans->to_send == NULL) {
		trans->to_send = timeout_add_short(0,
			smtp_client_transaction_submit_more, trans);
	}
	if (trans->finish_timeout_msecs > 0) {
		i_assert(trans->to_finish == NULL);
		trans->to_finish = timeout_add(trans->finish_timeout_msecs,
			smtp_client_transaction_timeout, trans);
	}
}

static void
smtp_client_transaction_try_complete(struct smtp_client_transaction *trans)
{
	struct smtp_client_connection *conn = trans->conn;

	if (array_count(&trans->rcpts_pending) > 0) {
		/* Not all RCPT replies have come in yet */
		smtp_client_transaction_debug(
			trans, "RCPT replies are still pending (%u/%u)",
			array_count(&trans->rcpts_pending),
			(array_count(&trans->rcpts_pending) +
			 array_count(&trans->rcpts)));
		return;
	}
	if (!trans->data_provided) {
		/* Still waiting for application to issue
		   smtp_client_transaction_send() */
		smtp_client_transaction_debug(
			trans, "Transaction is not yet complete");
		return;
	}

	if (trans->state == SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO) {
		/* Completed at this instance */
		smtp_client_transaction_debug(
			trans, "Got all RCPT replies and "
			"transaction is complete");
	}

	/* Entering DATA state */
	trans->state = SMTP_CLIENT_TRANSACTION_STATE_DATA;

	if (array_count(&trans->rcpts) == 0) {
		/* abort transaction if all recipients failed */
		smtp_client_transaction_abort(trans);
		return;
	}

	if (trans->cmd_data == NULL)
		return;

	if (conn->protocol == SMTP_PROTOCOL_LMTP) {
		smtp_client_command_set_replies(trans->cmd_data,
						array_count(&trans->rcpts));
	}

	/* Got replies for all recipients and submitted our last command;
	   the next transaction can submit its commands now. */
	smtp_client_connection_next_transaction(trans->conn, trans);
}

void smtp_client_transaction_connection_result(
	struct smtp_client_transaction *trans,
	const struct smtp_reply *reply)
{
	if (!smtp_reply_is_success(reply)) {
		if (trans->state <= SMTP_CLIENT_TRANSACTION_STATE_PENDING) {
			smtp_client_transaction_debug(trans,
				"Failed to connect: %s", smtp_reply_log(reply));
		} else {
			smtp_client_transaction_debug(trans,
				"Connection lost: %s", smtp_reply_log(reply));
		}
		smtp_client_transaction_fail_reply(trans, reply);
		return;
	}

	smtp_client_transaction_connection_ready(trans);
}

const struct smtp_client_transaction_times *
smtp_client_transaction_get_times(struct smtp_client_transaction *trans)
{
	return &trans->times;
}

enum smtp_client_transaction_state
smtp_client_transaction_get_state(struct smtp_client_transaction *trans)
{
	return trans->state;
}

const char *
smtp_client_transaction_get_state_name(struct smtp_client_transaction *trans)
{
	i_assert(trans->state >= SMTP_CLIENT_TRANSACTION_STATE_NEW &&
		trans->state <= SMTP_CLIENT_TRANSACTION_STATE_ABORTED);
	return smtp_client_transaction_state_names[trans->state];
}

const char *
smtp_client_transaction_get_state_destription(
	struct smtp_client_transaction *trans)
{
	enum smtp_client_connection_state conn_state;

	switch (trans->state) {
	case SMTP_CLIENT_TRANSACTION_STATE_NEW:
		break;
	case SMTP_CLIENT_TRANSACTION_STATE_PENDING:
		conn_state = smtp_client_connection_get_state(trans->conn);
		switch (conn_state) {
		case SMTP_CLIENT_CONNECTION_STATE_CONNECTING:
		case SMTP_CLIENT_CONNECTION_STATE_HANDSHAKING:
		case SMTP_CLIENT_CONNECTION_STATE_AUTHENTICATING:
			return smtp_client_connection_state_names[conn_state];
		case SMTP_CLIENT_CONNECTION_STATE_TRANSACTION:
			return "waiting for connection";
		case SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED:
		case SMTP_CLIENT_CONNECTION_STATE_READY:
		default:
			break;
		}
		break;
	case SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM:
		return "waiting for reply to MAIL FROM";
	case SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO:
		return "waiting for reply to RCPT TO";
	case SMTP_CLIENT_TRANSACTION_STATE_DATA:
		return "waiting for reply to DATA";
	case SMTP_CLIENT_TRANSACTION_STATE_FINISHED:
		return "finished";
	case SMTP_CLIENT_TRANSACTION_STATE_ABORTED:
		return "aborted";
	}
	i_unreached();
}

void smtp_client_transaction_switch_ioloop(
	struct smtp_client_transaction *trans)
{
	if (trans->to_send != NULL)
		trans->to_send = io_loop_move_timeout(&trans->to_send);
	if (trans->to_finish != NULL)
		trans->to_finish = io_loop_move_timeout(&trans->to_finish);
}
