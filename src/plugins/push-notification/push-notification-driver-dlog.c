/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-txn-mbox.h"
#include "push-notification-txn-msg.h"

static int
push_notification_driver_dlog_init(
	struct push_notification_driver_config *config,
	struct mail_user *user ATTR_UNUSED, pool_t pool ATTR_UNUSED,
	void **context ATTR_UNUSED, const char **error_r ATTR_UNUSED)
{
	i_debug("Called init push_notification plugin hook.");

	if (config->raw_config != NULL) {
		i_debug("Config string for dlog push_notification driver: %s",
			config->raw_config);
	}

	return 0;
}

static bool
push_notification_driver_dlog_begin_txn(
	struct push_notification_driver_txn *dtxn)
{
	const struct push_notification_event *const *event;

	i_debug("Called begin_txn push_notification plugin hook.");

	array_foreach(&push_notification_events, event) {
		push_notification_event_init(dtxn, (*event)->name, NULL);
	}

	return TRUE;
}

static void
push_notification_driver_dlog_process_mbox(
	struct push_notification_driver_txn *dtxn ATTR_UNUSED,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_txn_event *const *event;

	i_debug("Called process_mbox push_notification plugin hook.");

	i_debug("Mailbox data: Mailbox [%s]", mbox->mailbox);

	if (array_is_created(&mbox->eventdata)) {
		array_foreach(&mbox->eventdata, event) {
			if ((*event)->event->event->mbox.debug_mbox != NULL)
				(*event)->event->event->mbox.debug_mbox(*event);
		}
	}
}

static void
push_notification_driver_dlog_process_msg(
	struct push_notification_driver_txn *dtxn ATTR_UNUSED,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_txn_event *const *event;

	i_debug("Called process_msg push_notification plugin hook.");

	i_debug("Message data: Mailbox [%s], UID [%u], UIDVALIDITY [%u]",
		msg->mailbox, msg->uid, msg->uid_validity);

	if (array_is_created(&msg->eventdata)) {
		array_foreach(&msg->eventdata, event) {
			if ((*event)->event->event->msg.debug_msg != NULL) {
				(*event)->event->event->msg.debug_msg(*event);
			}
		}
	}
}

static void
push_notification_driver_dlog_end_txn(
	struct push_notification_driver_txn *dtxn ATTR_UNUSED,
	bool success ATTR_UNUSED)
{
	i_debug("Called end_txn push_notification plugin hook.");
}

static void
push_notification_driver_dlog_deinit(
	struct push_notification_driver_user *duser ATTR_UNUSED)
{
	i_debug("Called deinit push_notification plugin hook.");
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
