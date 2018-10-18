/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
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
	"reset",
	"finished",
	"aborted"
};

static void
smtp_client_transaction_submit_more(struct smtp_client_transaction *trans);
static void
smtp_client_transaction_submit(struct smtp_client_transaction *trans,
			       bool start);

static void
smtp_client_transaction_try_complete(struct smtp_client_transaction *trans);

static void
smtp_client_transaction_send_data(struct smtp_client_transaction *trans);
static void
smtp_client_transaction_send_reset(struct smtp_client_transaction *trans);

/*
 * Sender
 */

static struct smtp_client_transaction_mail *
smtp_client_transaction_mail_new(struct smtp_client_transaction *trans,
				 const struct smtp_address *mail_from,
				 const struct smtp_params_mail *mail_params)
{
	struct smtp_client_transaction_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("smtp transaction mail", 512);
	mail = p_new(pool, struct smtp_client_transaction_mail, 1);
	mail->pool = pool;
	mail->trans = trans;
	mail->mail_from = smtp_address_clone(pool, mail_from);
	smtp_params_mail_copy(pool, &mail->mail_params, mail_params);

	DLLIST2_APPEND(&trans->mail_head, &trans->mail_tail, mail);
	if (trans->mail_send == NULL)
		trans->mail_send = mail;

	return mail;
}

static void
smtp_client_transaction_mail_free(struct smtp_client_transaction_mail **_mail)
{
	struct smtp_client_transaction_mail *mail = *_mail;
	struct smtp_client_transaction *trans = mail->trans;

	*_mail = NULL;

	if (mail->cmd_mail_from != NULL)
		smtp_client_command_abort(&mail->cmd_mail_from);
	DLLIST2_REMOVE(&trans->mail_head, &trans->mail_tail, mail);
	pool_unref(&mail->pool);
}

void smtp_client_transaction_mail_abort(
	struct smtp_client_transaction_mail **_mail)
{
	struct smtp_client_transaction_mail *mail = *_mail;
	struct smtp_client_transaction *trans = mail->trans;

	i_assert(trans->state <= SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM ||
		 trans->state == SMTP_CLIENT_TRANSACTION_STATE_ABORTED);

	smtp_client_transaction_mail_free(_mail);
}

/*
 * Recipient
 */

static struct smtp_client_transaction_rcpt *
smtp_client_transaction_rcpt_new(
	struct smtp_client_transaction *trans, pool_t pool,
	const struct smtp_address *rcpt_to,
	const struct smtp_params_rcpt *rcpt_params)
{
	struct smtp_client_transaction_rcpt *rcpt;

	pool_ref(pool);

	rcpt = p_new(pool, struct smtp_client_transaction_rcpt, 1);
	rcpt->pool = pool;
	rcpt->trans = trans;
	rcpt->rcpt_to = smtp_address_clone(pool, rcpt_to);
	smtp_params_rcpt_copy(pool, &rcpt->rcpt_params, rcpt_params);

	DLLIST2_APPEND(&trans->rcpts_queue_head, &trans->rcpts_queue_tail,
		       rcpt);
	trans->rcpts_queue_count++;
	rcpt->queued = TRUE;
	if (trans->rcpts_send == NULL)
		trans->rcpts_send = rcpt;
	return rcpt;
}

static void
smtp_client_transaction_rcpt_free(
	struct smtp_client_transaction_rcpt **_rcpt)
{
	struct smtp_client_transaction_rcpt *rcpt = *_rcpt;
	struct smtp_client_transaction *trans = rcpt->trans;

	*_rcpt = NULL;

	if (trans->rcpts_send == rcpt)
		trans->rcpts_send = rcpt->next;
	if (trans->rcpts_data == rcpt)
		trans->rcpts_data = rcpt->next;
	if (rcpt->queued) {
		DLLIST2_REMOVE(&trans->rcpts_queue_head,
			       &trans->rcpts_queue_tail, rcpt);
		trans->rcpts_queue_count--;
	} else {
		DLLIST2_REMOVE(&trans->rcpts_head,
			       &trans->rcpts_tail, rcpt);
		trans->rcpts_count--;
	}

	if (rcpt->queued || rcpt->external_pool) {
		i_assert(rcpt->pool != NULL);
		pool_unref(&rcpt->pool);
	}
}

static void
smtp_client_transaction_rcpt_drop_pending(
	struct smtp_client_transaction_rcpt *rcpt)
{
	struct smtp_client_transaction *trans = rcpt->trans;

	i_assert(rcpt->queued);

	if (rcpt->external_pool) {
		rcpt->queued = FALSE;
		if (trans->rcpts_send == rcpt)
			trans->rcpts_send = rcpt->next;
		DLLIST2_REMOVE(&trans->rcpts_queue_head,
			       &trans->rcpts_queue_tail, rcpt);
		trans->rcpts_queue_count--;
		return;
	}

	smtp_client_transaction_rcpt_free(&rcpt);
}

static void
smtp_client_transaction_rcpt_approved(
	struct smtp_client_transaction_rcpt **_rcpt)
{
	struct smtp_client_transaction_rcpt *prcpt = *_rcpt;
	struct smtp_client_transaction *trans = prcpt->trans;
	struct smtp_client_transaction_rcpt *rcpt;
	pool_t pool;

	if (prcpt->external_pool)
		rcpt = prcpt;
	else {
		/* move to transaction pool */
		pool = trans->pool;
		rcpt = p_new(pool, struct smtp_client_transaction_rcpt, 1);
		rcpt->trans = trans;
		rcpt->rcpt_to = smtp_address_clone(pool, prcpt->rcpt_to);
		smtp_params_rcpt_copy(pool, &rcpt->rcpt_params,
				      &prcpt->rcpt_params);
		rcpt->data_callback = prcpt->data_callback;
		rcpt->data_context = prcpt->data_context;
	}

	/* not pending anymore */
	smtp_client_transaction_rcpt_drop_pending(prcpt);

	/* recipient is approved */
	DLLIST2_APPEND(&trans->rcpts_head, &trans->rcpts_tail, rcpt);
	trans->rcpts_count++;
	if (trans->rcpts_data == NULL)
		trans->rcpts_data = trans->rcpts_head;

	*_rcpt = rcpt;
}

static void
smtp_client_transaction_rcpt_denied(
	struct smtp_client_transaction_rcpt **_rcpt)
{
	struct smtp_client_transaction_rcpt *prcpt = *_rcpt;

	*_rcpt = NULL;

	/* not pending anymore */
	smtp_client_transaction_rcpt_free(&prcpt);
}

void smtp_client_transaction_rcpt_abort(
	struct smtp_client_transaction_rcpt **_rcpt)
{
	struct smtp_client_transaction_rcpt *rcpt = *_rcpt;
	struct smtp_client_transaction *trans = rcpt->trans;

	i_assert(rcpt->queued || rcpt->external_pool);

	i_assert(trans->state <= SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO ||
		 trans->state == SMTP_CLIENT_TRANSACTION_STATE_ABORTED);

	smtp_client_transaction_rcpt_free(_rcpt);
}

#undef smtp_client_transaction_rcpt_set_data_callback
void smtp_client_transaction_rcpt_set_data_callback(
	struct smtp_client_transaction_rcpt *rcpt,
	smtp_client_command_callback_t *callback, void *context)
{
	rcpt->data_callback = callback;
	rcpt->data_context = context;
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

#undef smtp_client_transaction_create_empty
struct smtp_client_transaction *
smtp_client_transaction_create_empty(
	struct smtp_client_connection *conn,
	enum smtp_client_transaction_flags flags,
	smtp_client_transaction_callback_t *callback, void *context)
{
	struct smtp_client_transaction *trans;
	pool_t pool;

	if (conn->protocol == SMTP_PROTOCOL_LMTP)
		flags |= SMTP_CLIENT_TRANSACTION_FLAG_REPLY_PER_RCPT;

	pool = pool_alloconly_create("smtp transaction", 4096);
	trans = p_new(pool, struct smtp_client_transaction, 1);
	trans->refcount = 1;
	trans->pool = pool;
	trans->flags = flags;
	trans->callback = callback;
	trans->context = context;

	trans->conn = conn;
	smtp_client_connection_ref(conn);

	smtp_client_transaction_debug(trans, "Created");

	return trans;
}

#undef smtp_client_transaction_create
struct smtp_client_transaction *
smtp_client_transaction_create(struct smtp_client_connection *conn,
	const struct smtp_address *mail_from,
	const struct smtp_params_mail *mail_params,
	enum smtp_client_transaction_flags flags,
	smtp_client_transaction_callback_t *callback, void *context)
{
	struct smtp_client_transaction *trans;

	trans = smtp_client_transaction_create_empty(conn, flags,
						     callback, context);
	(void)smtp_client_transaction_mail_new(trans, mail_from, mail_params);
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
	while (trans->mail_head != NULL) {
		struct smtp_client_transaction_mail *mail = trans->mail_head;

		if (mail->cmd_mail_from != NULL)
			smtp_client_command_abort(&mail->cmd_mail_from);
		smtp_client_transaction_mail_free(&mail);
	}
	while (trans->rcpts_queue_count > 0) {
		struct smtp_client_transaction_rcpt *rcpt =
			trans->rcpts_queue_head;

		if (rcpt->cmd_rcpt_to != NULL)
			smtp_client_command_abort(&rcpt->cmd_rcpt_to);
		smtp_client_transaction_rcpt_free(&rcpt);
	}
	if (trans->cmd_data != NULL)
		smtp_client_command_abort(&trans->cmd_data);
	if (trans->cmd_rset != NULL)
		smtp_client_command_abort(&trans->cmd_rset);
	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);
	trans->cmd_data = NULL;
	trans->cmd_rset = NULL;
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

	if (trans == NULL)
		return;

	i_assert(trans->refcount > 0);
	if (--trans->refcount > 0)
		return;

	smtp_client_transaction_debug(trans, "Destroy");

	i_stream_unref(&trans->data_input);
	smtp_client_transaction_abort(trans);

	while (trans->rcpts_count > 0) {
		struct smtp_client_transaction_rcpt *rcpt =
			trans->rcpts_head;
		smtp_client_transaction_rcpt_free(&rcpt);
	}

	i_assert(trans->state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED);
	pool_unref(&trans->pool);

	smtp_client_connection_unref(&conn);
}

void smtp_client_transaction_destroy(struct smtp_client_transaction **_trans)
{
	struct smtp_client_transaction *trans = *_trans;
	struct smtp_client_transaction_mail *mail;
	struct smtp_client_transaction_rcpt *rcpt;

	*_trans = NULL;

	if (trans == NULL)
		return;

	smtp_client_transaction_ref(trans);
	smtp_client_transaction_abort(trans);

	/* Make sure this transaction doesn't produce any more callbacks.
	   We cannot fully abort (destroy) these commands, as this may be
	   called from a callback. */
	for (mail = trans->mail_head; mail != NULL; mail = mail->next) {
		if (mail->cmd_mail_from != NULL)
			smtp_client_command_drop_callback(mail->cmd_mail_from);
	}
	for (rcpt = trans->rcpts_queue_head; rcpt != NULL; rcpt = rcpt->next) {
		if (rcpt->cmd_rcpt_to != NULL)
			smtp_client_command_drop_callback(rcpt->cmd_rcpt_to);
	}
	if (trans->cmd_data != NULL)
		smtp_client_command_drop_callback(trans->cmd_data);
	if (trans->cmd_rset != NULL)
		smtp_client_command_drop_callback(trans->cmd_rset);
	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);

	/* Free any approved recipients early */
	while (trans->rcpts_count > 0) {
		struct smtp_client_transaction_rcpt *rcpt =
			trans->rcpts_head;
		smtp_client_transaction_rcpt_free(&rcpt);
	}

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
	struct smtp_client_transaction_rcpt *rcpt, *rcpt_next;

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
	while (trans->mail_head != NULL) {
		struct smtp_client_transaction_mail *mail = trans->mail_head;

		if (mail->cmd_mail_from != NULL)
			smtp_client_command_abort(&mail->cmd_mail_from);
		if (mail->mail_callback != NULL)
			mail->mail_callback(reply, mail->context);
		smtp_client_transaction_mail_free(&mail);
	}

	/* RCPT */
	rcpt = trans->rcpts_queue_head;
	while (rcpt != NULL) {
		struct smtp_client_command *cmd = rcpt->cmd_rcpt_to;

		if (rcpt->failed) {
			rcpt = rcpt->next;
			continue;
		}
		rcpt_next = rcpt->next;

		rcpt->cmd_rcpt_to = NULL;
		rcpt->failed = TRUE;

		if (cmd != NULL) {
			smtp_client_command_fail_reply(&cmd, reply);
		} else {
			if (rcpt->rcpt_callback != NULL) {
				rcpt->rcpt_callback(reply, rcpt->context);
			}
			rcpt->rcpt_callback = NULL;
		}

		rcpt = rcpt_next;
	}

	/* DATA / RSET */
	if (!trans->data_provided && !trans->reset) {
		/* none of smtp_client_transaction_send() and
		   smtp_client_transaction_reset() was called so far
		 */
	} else if (trans->cmd_data != NULL) {
		/* the DATA command is still pending; handle the failure by
		   failing the DATA command. */
		smtp_client_command_fail_reply(&trans->cmd_data, reply);
	} else if (trans->cmd_rset != NULL) {
		/* the RSET command is still pending; handle the failure by
		   failing the RSET command. */
		smtp_client_command_fail_reply(&trans->cmd_rset, reply);
	} else {
		i_assert(!trans->reset);

		/* the DATA command was not sent yet; call all DATA callbacks
		   for the recipients that were previously accepted. */
		for (rcpt = trans->rcpts_data; rcpt != NULL;
		     rcpt = rcpt->next) {
			if (rcpt->data_callback != NULL) {
				rcpt->data_callback(reply, rcpt->data_context);
			}
			rcpt->data_callback = NULL;
		}
		if (trans->data_callback != NULL)
			trans->data_callback(reply, trans->data_context);
		trans->data_callback = NULL;
	}

	/* plug */
	if (trans->failure == NULL)
		trans->failure = smtp_reply_clone(trans->pool, reply);
	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);
	trans->cmd_plug = NULL;

	trans->failing = FALSE;

	if (trans->data_provided || trans->reset) {
		/* abort the transaction only if smtp_client_transaction_send()
		   or  smtp_client_transaction_reset() was called (and if it is
		   not aborted already) */
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
	struct smtp_client_transaction_mail *mail = trans->mail_head;
	bool success = smtp_reply_is_success(reply);

	smtp_client_transaction_debug(trans, "Got MAIL reply: %s",
		smtp_reply_log(reply));

	i_assert(mail != NULL);

	if (success) {
		if (trans->sender_accepted) {
			smtp_client_transaction_fail(
				trans, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
				"Server accepted more than a single MAIL command.");
			return;
		}
		trans->mail_failure = NULL;
		trans->sender_accepted = TRUE;
	}

	/* plug command line pipeline if no RCPT commands are yet issued */
	if (!trans->immediate && mail->next == NULL &&
	    mail->cmd_mail_from == trans->cmd_last) {
		trans->cmd_plug = trans->cmd_last =
			smtp_client_command_plug(trans->conn, trans->cmd_last);
	}
	mail->cmd_mail_from = NULL;

	if (trans->rcpts_queue_count > 0)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO;
	else if (trans->reset)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RESET;

	if (mail->mail_callback != NULL) {
		enum smtp_client_transaction_state state;
		struct smtp_client_transaction *tmp_trans = trans;

		smtp_client_transaction_ref(tmp_trans);
		mail->mail_callback(reply, mail->context);
		state = trans->state;
		smtp_client_transaction_unref(&tmp_trans);
		if (state >= SMTP_CLIENT_TRANSACTION_STATE_FINISHED)
			return;
	}

	smtp_client_transaction_mail_free(&mail);

	if (!success && !trans->sender_accepted) {
		if (trans->state > SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
			smtp_client_transaction_fail_reply(trans, reply);
		else if (trans->mail_failure == NULL)
			trans->mail_failure = smtp_reply_clone(trans->pool, reply);
	}
}

#undef smtp_client_transaction_add_mail
struct smtp_client_transaction_mail *
smtp_client_transaction_add_mail(struct smtp_client_transaction *trans,
				 const struct smtp_address *mail_from,
				 const struct smtp_params_mail *mail_params,
				 smtp_client_command_callback_t *mail_callback,
				 void *context)
{
	struct smtp_client_transaction_mail *mail;

	smtp_client_transaction_debug(trans, "Add MAIL command");

	i_assert(!trans->data_provided);
	i_assert(!trans->reset);

	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO);

	mail = smtp_client_transaction_mail_new(trans, mail_from, mail_params);
	mail->mail_callback = mail_callback;
	mail->context = context;

	smtp_client_transaction_submit(trans, FALSE);

	return mail;
}

static void smtp_client_transaction_connection_ready(
	struct smtp_client_transaction *trans)
{
	if (trans->state != SMTP_CLIENT_TRANSACTION_STATE_PENDING)
		return;

	smtp_client_transaction_debug(trans,
		"Connecton is ready for transaction");

	trans->state = SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM;

	smtp_client_transaction_submit_more(trans);
}

#undef smtp_client_transaction_start
void smtp_client_transaction_start(
	struct smtp_client_transaction *trans,
	smtp_client_command_callback_t *mail_callback, void *context)
{
	struct smtp_client_connection *conn = trans->conn;
	struct smtp_client_transaction_mail *mail = trans->mail_head;

	i_assert(trans->state == SMTP_CLIENT_TRANSACTION_STATE_NEW);

	smtp_client_transaction_debug(trans, "Start");

	io_loop_time_refresh();
	trans->times.started = ioloop_timeval;

	i_assert(mail != NULL);
	i_assert(mail->mail_callback == NULL);

	mail->mail_callback = mail_callback;
	mail->context = context;

	trans->state = SMTP_CLIENT_TRANSACTION_STATE_PENDING;

	smtp_client_connection_add_transaction(conn, trans);

	if (trans->immediate) {
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM;

		if (!trans->submitting)
			smtp_client_transaction_submit_more(trans);
	}
}

#undef smtp_client_transaction_start_empty
void smtp_client_transaction_start_empty(
	struct smtp_client_transaction *trans,
	const struct smtp_address *mail_from,
	const struct smtp_params_mail *mail_params,
	smtp_client_command_callback_t *mail_callback, void *context)
{
	i_assert(trans->mail_head == NULL);

	(void)smtp_client_transaction_mail_new(trans, mail_from, mail_params);
	
	smtp_client_transaction_start(trans, mail_callback, context);
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
	if (!trans->immediate && !trans->reset &&
	    rcpt->cmd_rcpt_to == trans->cmd_last && trans->cmd_data == NULL) {
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

#undef smtp_client_transaction_add_rcpt
struct smtp_client_transaction_rcpt *
smtp_client_transaction_add_rcpt(struct smtp_client_transaction *trans,
				 const struct smtp_address *rcpt_to,
				 const struct smtp_params_rcpt *rcpt_params,
				 smtp_client_command_callback_t *rcpt_callback,
				 smtp_client_command_callback_t *data_callback,
				 void *context)
{
	struct smtp_client_transaction_rcpt *rcpt;
	pool_t pool;

	smtp_client_transaction_debug(trans, "Add recipient");

	i_assert(!trans->data_provided);
	i_assert(!trans->reset);

	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);

	if (trans->mail_head == NULL &&
		trans->state == SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO;

	pool = pool_alloconly_create("smtp transaction rcpt", 512);
	rcpt = smtp_client_transaction_rcpt_new(trans, pool,
						rcpt_to, rcpt_params);
	pool_unref(&pool);

	rcpt->rcpt_callback = rcpt_callback;
	rcpt->context = context;

	rcpt->data_callback = data_callback;
	rcpt->data_context = context;

	smtp_client_transaction_submit(trans, FALSE);

	return rcpt;
}

#undef smtp_client_transaction_add_pool_rcpt
struct smtp_client_transaction_rcpt *
smtp_client_transaction_add_pool_rcpt(
	struct smtp_client_transaction *trans, pool_t pool,
	const struct smtp_address *rcpt_to,
	const struct smtp_params_rcpt *rcpt_params,
	smtp_client_command_callback_t *rcpt_callback, void *context)
{
	struct smtp_client_transaction_rcpt *rcpt;

	smtp_client_transaction_debug(trans, "Add recipient (external pool)");

	i_assert(!trans->data_provided);
	i_assert(!trans->reset);

	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);

	if (trans->mail_head == NULL &&
		trans->state == SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO;

	rcpt = smtp_client_transaction_rcpt_new(trans, pool,
						rcpt_to, rcpt_params);
	rcpt->rcpt_callback = rcpt_callback;
	rcpt->context = context;
	rcpt->external_pool = TRUE;

	smtp_client_transaction_submit(trans, FALSE);

	return rcpt;
}

static void
smtp_client_transaction_data_cb(const struct smtp_reply *reply,
				struct smtp_client_transaction *trans)
{
	i_assert(!trans->reset);

	smtp_client_transaction_ref(trans);

	if (HAS_ALL_BITS(trans->flags,
			 SMTP_CLIENT_TRANSACTION_FLAG_REPLY_PER_RCPT) &&
	    trans->cmd_data != NULL && /* NULL when failed early */
	    trans->rcpts_data == NULL && trans->rcpts_count > 0) {
		smtp_client_command_set_replies(trans->cmd_data,
						trans->rcpts_count);
	}
	while (trans->rcpts_data != NULL) {
		struct smtp_client_transaction_rcpt *rcpt = trans->rcpts_data;

		trans->rcpts_data = trans->rcpts_data->next;
		if (rcpt->data_callback != NULL)
			rcpt->data_callback(reply, rcpt->data_context);
		rcpt->data_callback = NULL;
		if (HAS_ALL_BITS(trans->flags,
				 SMTP_CLIENT_TRANSACTION_FLAG_REPLY_PER_RCPT))
			break;
	}
	if (trans->rcpts_data != NULL) {
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

	i_assert(!trans->reset);
	i_assert(trans->data_input != NULL);

	smtp_client_transaction_debug(trans, "Sending data");

	timeout_remove(&trans->to_send);

	if (trans->failure != NULL) {
		smtp_client_transaction_fail_reply(trans, trans->failure);
		finished = TRUE;
	} else if ((trans->rcpts_count + trans->rcpts_queue_count) == 0) {
		smtp_client_transaction_debug(trans, "No valid recipients");
		finished = TRUE;
	} else {
		trans->cmd_data = smtp_client_command_data_submit_after(
			trans->conn, 0, trans->cmd_last, trans->data_input,
			smtp_client_transaction_data_cb, trans);
		trans->submitted_data = TRUE;

		if (trans->cmd_last != NULL)
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
	i_assert(!trans->data_provided);
	i_assert(!trans->reset);

	if (trans->rcpts_queue_count == 0)
		smtp_client_transaction_debug(trans, "Got all RCPT replies");

	smtp_client_transaction_debug(trans, "Send");

	trans->data_provided = TRUE;

	i_assert(trans->data_input == NULL);
	trans->data_input = data_input;
	i_stream_ref(data_input);

	trans->data_callback = data_callback;
	trans->data_context = data_context;

	if (trans->finish_timeout_msecs > 0) {
		i_assert(trans->to_finish == NULL);
		trans->to_finish = timeout_add(trans->finish_timeout_msecs,
			smtp_client_transaction_timeout, trans);
	}

	smtp_client_transaction_submit(trans, TRUE);
}

static void
smtp_client_transaction_rset_cb(const struct smtp_reply *reply,
				struct smtp_client_transaction *trans)
{
	smtp_client_transaction_ref(trans);

	trans->cmd_rset = NULL;

	if (trans->reset_callback != NULL)
		trans->reset_callback(reply, trans->reset_context);
	trans->reset_callback = NULL;

	/* finished */
	smtp_client_transaction_finish(trans);

	smtp_client_transaction_unref(&trans);
}

static void
smtp_client_transaction_send_reset(struct smtp_client_transaction *trans)
{
	i_assert(trans->reset);

	smtp_client_transaction_debug(trans, "Sending reset");

	timeout_remove(&trans->to_send);

	trans->cmd_rset = smtp_client_command_rset_submit_after(
		trans->conn, 0, trans->cmd_last,
		smtp_client_transaction_rset_cb, trans);

	if (trans->cmd_last != NULL)
		smtp_client_command_unlock(trans->cmd_last);

	smtp_client_transaction_try_complete(trans);

	if (trans->cmd_plug != NULL)
		smtp_client_command_abort(&trans->cmd_plug);
	trans->cmd_last = NULL;
}

#undef smtp_client_transaction_reset
void smtp_client_transaction_reset(
	struct smtp_client_transaction *trans,
	smtp_client_command_callback_t *reset_callback, void *reset_context)
{
	i_assert(trans->state < SMTP_CLIENT_TRANSACTION_STATE_FINISHED);
	i_assert(!trans->data_provided);
	i_assert(!trans->reset);

	smtp_client_transaction_debug(trans, "Reset");

	trans->reset = TRUE;

	trans->reset_callback = reset_callback;
	trans->reset_context = reset_context;

	if (trans->finish_timeout_msecs > 0) {
		i_assert(trans->to_finish == NULL);
		trans->to_finish = timeout_add(trans->finish_timeout_msecs,
			smtp_client_transaction_timeout, trans);
	}

	smtp_client_transaction_submit(trans, TRUE);
}

static void
smtp_client_transaction_do_submit_more(struct smtp_client_transaction *trans)
{
	timeout_remove(&trans->to_send);

	if (trans->immediate)
		trans->cmd_last = NULL;

	/* Check whether we already failed */
	if (trans->failure == NULL &&
	    trans->state > SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
		trans->failure = trans->mail_failure;
	if (trans->failure != NULL) {
		smtp_client_transaction_fail_reply(trans, trans->failure);
		return;
	}

	/* Make sure transaction is started */
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

	/* MAIL */
	if (trans->mail_send != NULL) {
		smtp_client_transaction_debug(trans, "Sending MAIL command");

		i_assert(trans->state == SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM);

		if (trans->cmd_last != NULL)
			smtp_client_command_unlock(trans->cmd_last);

		while (trans->mail_send != NULL) {
			struct smtp_client_transaction_mail *mail =
				trans->mail_send;

			trans->mail_send = trans->mail_send->next;
			mail->cmd_mail_from = trans->cmd_last =
				smtp_client_command_mail_submit(trans->conn, 0,
					mail->mail_from, &mail->mail_params,
					smtp_client_transaction_mail_cb, trans);
		}

		if (!trans->immediate)
			smtp_client_command_lock(trans->cmd_last);
	}

	/* RCPT */
	if (trans->rcpts_send != NULL) {
		smtp_client_transaction_debug(trans, "Sending recipients");

		if (trans->cmd_last != NULL)
			smtp_client_command_unlock(trans->cmd_last);

		while (trans->rcpts_send != NULL) {
			struct smtp_client_transaction_rcpt *rcpt =
				trans->rcpts_send;

			trans->rcpts_send = trans->rcpts_send->next;
			rcpt->cmd_rcpt_to = trans->cmd_last =
				smtp_client_command_rcpt_submit_after(
					trans->conn, 0,	trans->cmd_last,
					rcpt->rcpt_to, &rcpt->rcpt_params,
					smtp_client_transaction_rcpt_cb, rcpt);
		}
		if (!trans->immediate)
			smtp_client_command_lock(trans->cmd_last);
	}

	if (trans->cmd_plug != NULL &&
	    (trans->immediate || trans->cmd_last != trans->cmd_plug))
		smtp_client_command_abort(&trans->cmd_plug);

	/* DATA / RSET */
	if (trans->reset) {
		smtp_client_transaction_send_reset(trans);
	} else if (trans->data_input != NULL) {
		smtp_client_transaction_send_data(trans);
	}
}

static void
smtp_client_transaction_submit_more(struct smtp_client_transaction *trans)
{
	smtp_client_transaction_ref(trans);
	trans->submitting = TRUE;
	smtp_client_transaction_do_submit_more(trans);
	trans->submitting = FALSE;
	smtp_client_transaction_unref(&trans);
}

static void
smtp_client_transaction_submit(struct smtp_client_transaction *trans,
			       bool start)
{
	if (trans->failure == NULL && !start &&
	    trans->state <= SMTP_CLIENT_TRANSACTION_STATE_PENDING) {
		/* Cannot submit commands at this time */
		return;
	}

	if (trans->immediate) {
		/* Submit immediately if not failed already: avoid calling
		   failure callbacks directly (which is the first thing
		   smtp_client_transaction_submit_more() would do). */
		if (trans->failure == NULL &&
		    trans->state > SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM)
			trans->failure = trans->mail_failure;
		if (trans->failure == NULL) {
			smtp_client_transaction_submit_more(trans);
			return;
		}
	}

	if (trans->to_send != NULL) {
		/* Already scheduled command submission */
		return;
	}

	trans->to_send = timeout_add_short(0,
		smtp_client_transaction_submit_more, trans);
}

static void
smtp_client_transaction_try_complete(struct smtp_client_transaction *trans)
{
	if (trans->rcpts_queue_count > 0) {
		/* Not all RCPT replies have come in yet */
		smtp_client_transaction_debug(
			trans, "RCPT replies are still pending (%u/%u)",
			trans->rcpts_queue_count,
			(trans->rcpts_queue_count + trans->rcpts_count));
		return;
	}
	if (!trans->data_provided && !trans->reset) {
		/* Still waiting for application to issue either
		   smtp_client_transaction_send() or
		   smtp_client_transaction_reset() */
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

	if (trans->reset) {
		/* Entering reset state */
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_RESET;

		if (trans->cmd_rset == NULL)
			return;
	} else {
		/* Entering data state */
		trans->state = SMTP_CLIENT_TRANSACTION_STATE_DATA;

		if (trans->rcpts_count == 0) {
			/* abort transaction if all recipients failed */
			smtp_client_transaction_abort(trans);
			return;
		}

		if (trans->cmd_data == NULL)
			return;

		if (HAS_ALL_BITS(trans->flags,
				 SMTP_CLIENT_TRANSACTION_FLAG_REPLY_PER_RCPT)) {
			smtp_client_command_set_replies(trans->cmd_data,
							trans->rcpts_count);
		}
	}

	/* Got replies for all recipients and submitted our last command;
	   the next transaction can submit its commands now. */
	smtp_client_connection_next_transaction(trans->conn, trans);
}

void smtp_client_transaction_set_immediate(
	struct smtp_client_transaction *trans, bool immediate)
{
	trans->immediate = immediate;
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
	case SMTP_CLIENT_TRANSACTION_STATE_RESET:
		return "waiting for reply to RESET";
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
