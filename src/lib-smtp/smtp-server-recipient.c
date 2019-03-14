/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "smtp-address.h"

#include "smtp-server-private.h"

static bool
smtp_server_recipient_call_hooks(struct smtp_server_recipient **_rcpt,
				 enum smtp_server_recipient_hook_type type);

static void
smtp_server_recipient_update_event(struct smtp_server_recipient_private *prcpt)
{
	struct event *event = prcpt->rcpt.event;
	const char *path = smtp_address_encode(prcpt->rcpt.path);

	event_add_str(event, "rcpt_to", path);
	smtp_params_rcpt_add_to_event(&prcpt->rcpt.params, event);
	event_set_append_log_prefix(event,
				    t_strdup_printf("rcpt %s: ", path));
}

struct smtp_server_recipient *
smtp_server_recipient_create(struct smtp_server_cmd_ctx *cmd,
			     const struct smtp_address *rcpt_to,
			     const struct smtp_params_rcpt *params)
{
	struct smtp_server_recipient_private *prcpt;
	pool_t pool;

	pool = pool_alloconly_create("smtp server recipient", 512);
	prcpt = p_new(pool, struct smtp_server_recipient_private, 1);
	prcpt->refcount = 1;
	prcpt->rcpt.pool = pool;
	prcpt->rcpt.conn = cmd->conn;
	prcpt->rcpt.cmd = cmd;
	prcpt->rcpt.path = smtp_address_clone(pool, rcpt_to);
	smtp_params_rcpt_copy(pool, &prcpt->rcpt.params, params);

	prcpt->rcpt.event = event_create(cmd->conn->event);
	smtp_server_recipient_update_event(prcpt);

	return &prcpt->rcpt;
}

void smtp_server_recipient_ref(struct smtp_server_recipient *rcpt)
{
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;

	if (prcpt->destroying)
		return;
	i_assert(prcpt->refcount > 0);
	prcpt->refcount++;
}

bool smtp_server_recipient_unref(struct smtp_server_recipient **_rcpt)
{
	struct smtp_server_recipient *rcpt = *_rcpt;
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;

	*_rcpt = NULL;

	if (rcpt == NULL)
		return FALSE;
	if (prcpt->destroying)
		return FALSE;

	i_assert(prcpt->refcount > 0);
	if (--prcpt->refcount > 0)
		return TRUE;
	prcpt->destroying = TRUE;

	if (!smtp_server_recipient_call_hooks(
		&rcpt, SMTP_SERVER_RECIPIENT_HOOK_DESTROY))
		i_unreached();

	if (!rcpt->finished) {
		struct event_passthrough *e =
			e = event_create_passthrough(rcpt->event)->
			set_name("smtp_server_transaction_rcpt_finished");
		e->add_int("status_code", 9000);
		e->add_str("enhanced_code", "9.0.0");
		e->add_str("error", "Aborted");

		e_debug(e->event(), "Aborted");
	}

	event_unref(&rcpt->event);
	pool_unref(&rcpt->pool);
	return FALSE;
}

void smtp_server_recipient_destroy(struct smtp_server_recipient **_rcpt)
{
	smtp_server_recipient_unref(_rcpt);
}

bool smtp_server_recipient_approved(struct smtp_server_recipient **_rcpt)
{
	struct smtp_server_recipient *rcpt = *_rcpt;
	struct smtp_server_transaction *trans = rcpt->conn->state.trans;

	i_assert(trans != NULL);

	e_debug(rcpt->event, "Approved");

	rcpt->cmd = NULL;
	smtp_server_transaction_add_rcpt(trans, rcpt);

	return smtp_server_recipient_call_hooks(
		_rcpt, SMTP_SERVER_RECIPIENT_HOOK_APPROVED);
}

void smtp_server_recipient_denied(struct smtp_server_recipient *rcpt,
				  const struct smtp_server_reply *reply)
{
	i_assert(!rcpt->finished);
	rcpt->finished = TRUE;

	struct event_passthrough *e =
		event_create_passthrough(rcpt->event)->
		set_name("smtp_server_transaction_rcpt_finished");
	smtp_server_reply_add_to_event(reply, e);

	e_debug(e->event(), "Denied");
}

void smtp_server_recipient_last_data(struct smtp_server_recipient *rcpt,
				     struct smtp_server_cmd_ctx *cmd)
{
	i_assert(rcpt->cmd == NULL);
	rcpt->cmd = cmd;
}

void smtp_server_recipient_replyv(struct smtp_server_recipient *rcpt,
				  unsigned int status, const char *enh_code,
				  const char *fmt, va_list args)
{
	i_assert(rcpt->cmd != NULL);

	if (smtp_server_command_is_rcpt(rcpt->cmd) && (status / 100) == 2) {
		smtp_server_reply_indexv(rcpt->cmd, rcpt->index,
					 status, enh_code, fmt, args);
		return;
	}
		
	smtp_server_reply_index(rcpt->cmd, rcpt->index, status, enh_code,
				"<%s> %s", smtp_address_encode(rcpt->path),
				t_strdup_vprintf(fmt, args));
}

void smtp_server_recipient_reply(struct smtp_server_recipient *rcpt,
				 unsigned int status, const char *enh_code,
				 const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	smtp_server_recipient_replyv(rcpt, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_recipient_reset(struct smtp_server_recipient *rcpt)
{
	i_assert(!rcpt->finished);
	rcpt->finished = TRUE;

	struct event_passthrough *e =
		event_create_passthrough(rcpt->event)->
		set_name("smtp_server_transaction_rcpt_finished");
	e->add_int("status_code", 9000);
	e->add_str("enhanced_code", "9.0.0");
	e->add_str("error", "Reset");

	e_debug(e->event(), "Reset");
}

void smtp_server_recipient_finished(struct smtp_server_recipient *rcpt,
				    const struct smtp_server_reply *reply)
{
	i_assert(!rcpt->finished);
	rcpt->finished = TRUE;

	struct event_passthrough *e =
		event_create_passthrough(rcpt->event)->
		set_name("smtp_server_transaction_rcpt_finished");
	smtp_server_reply_add_to_event(reply, e);

	e_debug(e->event(), "Finished");
}

#undef smtp_server_recipient_add_hook
void smtp_server_recipient_add_hook(struct smtp_server_recipient *rcpt,
				    enum smtp_server_recipient_hook_type type,
				    smtp_server_rcpt_func_t func, void *context)
{
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;
	struct smtp_server_recipient_hook *hook;

	i_assert(func != NULL);

	hook = prcpt->hooks_head;
	while (hook != NULL) {
		/* no double registrations */
		i_assert(hook->type != type || hook->func != func);

		hook = hook->next;
	}

	hook = p_new(rcpt->pool, struct smtp_server_recipient_hook, 1);
	hook->type = type;
	hook->func = func;
	hook->context = context;

	DLLIST2_APPEND(&prcpt->hooks_head, &prcpt->hooks_tail, hook);
}

#undef smtp_server_recipient_remove_hook
void smtp_server_recipient_remove_hook(
	struct smtp_server_recipient *rcpt,
	enum smtp_server_recipient_hook_type type,
	smtp_server_rcpt_func_t *func)
{
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;
	struct smtp_server_recipient_hook *hook;
	bool found = FALSE;

	hook = prcpt->hooks_head;
	while (hook != NULL) {
		struct smtp_server_recipient_hook *hook_next = hook->next;

		if (hook->type == type && hook->func == func) {
			DLLIST2_REMOVE(&prcpt->hooks_head, &prcpt->hooks_tail,
				       hook);
			found = TRUE;
			break;
		}

		hook = hook_next;
	}
	i_assert(found);
}

static bool
smtp_server_recipient_call_hooks(struct smtp_server_recipient **_rcpt,
				 enum smtp_server_recipient_hook_type type)
{
	struct smtp_server_recipient *rcpt = *_rcpt;
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;
	struct smtp_server_recipient_hook *hook;

	if (type != SMTP_SERVER_RECIPIENT_HOOK_DESTROY)
		smtp_server_recipient_ref(rcpt);

	hook = prcpt->hooks_head;
	while (hook != NULL) {
		struct smtp_server_recipient_hook *hook_next = hook->next;

		if (hook->type == type) {
			DLLIST2_REMOVE(&prcpt->hooks_head, &prcpt->hooks_tail,
				       hook);
			hook->func(rcpt, hook->context);
		}

		hook = hook_next;
	}

	if (type != SMTP_SERVER_RECIPIENT_HOOK_DESTROY) {
		if (!smtp_server_recipient_unref(&rcpt)) {
			*_rcpt = NULL;
			return FALSE;
		}
	}
	return TRUE;
}
