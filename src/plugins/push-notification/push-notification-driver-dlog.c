/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include "mail-storage-private.h"
#include "push-notification-plugin.h"
#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-txn-mbox.h"
#include "push-notification-txn-msg.h"

#define DLOG_PREFIX "dlog: "

struct dlog_push_notification_context {
	struct event *event;
};

struct dlog_push_notification_txn_context {
	struct event *event;
};

static struct event *create_dlog_event(struct event *parent)
{
	struct event *event = event_create(parent);
	event_add_category(event, push_notification_get_event_category());
	event_set_append_log_prefix(event, DLOG_PREFIX);
	event_set_forced_debug(event, TRUE);
	return event;
}

static int
push_notification_driver_dlog_init(
	struct push_notification_driver_config *config,
	struct mail_user *user, pool_t pool,
	void **context, const char **error_r ATTR_UNUSED)
{
	struct event *log_event = create_dlog_event(user->event);
	struct dlog_push_notification_txn_context *ctx = p_new(
		pool, struct dlog_push_notification_txn_context, 1);
	ctx->event = log_event;
	*context = ctx;

	e_debug(log_event, "Called init push_notification plugin hook.");
	if (config->raw_config != NULL) {
		e_debug(log_event,
			"Config string for dlog push_notification driver: %s",
			config->raw_config);
	}

	return 0;
}

static bool
push_notification_driver_dlog_begin_txn(
	struct push_notification_driver_txn *dtxn)
{
	struct event *log_event = create_dlog_event(dtxn->ptxn->mbox->event);
	struct dlog_push_notification_txn_context *tctx = p_new(
		dtxn->ptxn->pool, struct dlog_push_notification_txn_context, 1);
	tctx->event = log_event;
	dtxn->context = tctx;

	e_debug(log_event, "Called begin_txn push_notification plugin hook.");

	const struct push_notification_event *event;
	array_foreach_elem(&push_notification_events, event)
		push_notification_event_init(dtxn, event->name, NULL, log_event);
	return TRUE;
}

static void
push_notification_driver_dlog_process_mbox(
	struct push_notification_driver_txn *dtxn,
	struct push_notification_txn_mbox *mbox)
{
	struct dlog_push_notification_txn_context *tctx = dtxn->context;
	e_debug(tctx->event, "Called process_mbox push_notification plugin hook.");
	e_debug(tctx->event, "Mailbox data: Mailbox [%s]", mbox->mailbox);

	struct push_notification_txn_event *event;
	if (array_is_created(&mbox->eventdata)) {
		array_foreach_elem(&mbox->eventdata, event) {
			if (event->event->event->mbox.debug_mbox != NULL)
				event->event->event->mbox.debug_mbox(event);
		}
	}
}

static void
push_notification_driver_dlog_process_msg(
	struct push_notification_driver_txn *dtxn ATTR_UNUSED,
	struct push_notification_txn_msg *msg)
{
	struct dlog_push_notification_txn_context *tctx = dtxn->context;
	e_debug(tctx->event, "Called process_msg push_notification plugin hook.");
	e_debug(tctx->event, "Message data: Mailbox [%s], UID [%u], UIDVALIDITY [%u]",
		msg->mailbox, msg->uid, msg->uid_validity);

	struct push_notification_txn_event *event;
	if (array_is_created(&msg->eventdata)) {
		array_foreach_elem(&msg->eventdata, event) {
			if (event->event->event->msg.debug_msg != NULL)
				event->event->event->msg.debug_msg(event);
		}
	}
}

static void
push_notification_driver_dlog_end_txn(
	struct push_notification_driver_txn *dtxn,
	bool success ATTR_UNUSED)
{
	struct dlog_push_notification_txn_context *tctx = dtxn->context;
	e_debug(tctx->event, "Called end_txn push_notification plugin hook.");
	event_unref(&tctx->event);
}

static void
push_notification_driver_dlog_deinit(
	struct push_notification_driver_user *duser)
{
	struct dlog_push_notification_context *ctx = duser->context;
	e_debug(ctx->event, "Called deinit push_notification plugin hook.");
	event_unref(&ctx->event);
}

static void push_notification_driver_dlog_cleanup(void)
{
	i_debug("Called cleanup push_notification plugin hook.");
}

/* Driver definition */

extern struct push_notification_driver push_notification_driver_dlog;

struct push_notification_driver push_notification_driver_dlog = {
	.name = "dlog",
	.v = {
		.init = push_notification_driver_dlog_init,
		.begin_txn = push_notification_driver_dlog_begin_txn,
		.process_mbox = push_notification_driver_dlog_process_mbox,
		.process_msg = push_notification_driver_dlog_process_msg,
		.end_txn = push_notification_driver_dlog_end_txn,
		.deinit = push_notification_driver_dlog_deinit,
		.cleanup = push_notification_driver_dlog_cleanup
	}
};
