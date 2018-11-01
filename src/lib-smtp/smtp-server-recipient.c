/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "smtp-address.h"

#include "smtp-server-private.h"

static void
smtp_server_recipient_call_hooks(struct smtp_server_recipient *rcpt,
				 enum smtp_server_recipient_hook_type type);

struct smtp_server_recipient *
smtp_server_recipient_create(struct smtp_server_cmd_ctx *cmd,
			     const struct smtp_address *rcpt_to)
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

	return &prcpt->rcpt;
}

void smtp_server_recipient_ref(struct smtp_server_recipient *rcpt)
{
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;

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

	i_assert(prcpt->refcount > 0);
	if (--prcpt->refcount > 0)
		return TRUE;

	smtp_server_recipient_call_hooks(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_DESTROY);

	pool_unref(&rcpt->pool);
	return FALSE;
}

void smtp_server_recipient_destroy(struct smtp_server_recipient **_rcpt)
{
	smtp_server_recipient_unref(_rcpt);
}

void smtp_server_recipient_approved(struct smtp_server_recipient *rcpt)
{
	struct smtp_server_transaction *trans = rcpt->conn->state.trans;

	i_assert(trans != NULL);

	rcpt->cmd = NULL;
	smtp_server_transaction_add_rcpt(trans, rcpt);

	smtp_server_recipient_call_hooks(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_APPROVED);
}

void smtp_server_recipient_last_data(struct smtp_server_recipient *rcpt,
				     struct smtp_server_cmd_ctx *cmd)
{
	i_assert(rcpt->cmd == NULL);
	rcpt->cmd = cmd;
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

static void
smtp_server_recipient_call_hooks(struct smtp_server_recipient *rcpt,
				 enum smtp_server_recipient_hook_type type)
{
	struct smtp_server_recipient_private *prcpt =
		(struct smtp_server_recipient_private *)rcpt;
	struct smtp_server_recipient_hook *hook;

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
}
