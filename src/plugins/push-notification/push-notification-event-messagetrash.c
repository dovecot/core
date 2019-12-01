/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-types.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-messagetrash.h"
#include "push-notification-txn-msg.h"

#define EVENT_NAME "MessageTrash"

static void
push_notification_event_messagetrash_debug_msg(
	struct push_notification_txn_event *event ATTR_UNUSED)
{
	i_debug("%s: Message was marked as deleted", EVENT_NAME);
}

static void
push_notification_event_messagetrash_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_msg *msg, struct mail *mail,
	enum mail_flags old_flags)
{
	struct push_notification_event_messagetrash_data *data;
	enum mail_flags flags;

	/* If data struct exists, that means the deleted flag was changed. */
	data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
	if ((data == NULL) && (old_flags & MAIL_DELETED) == 0) {
		flags = mail_get_flags(mail);
		if ((flags & MAIL_DELETED) != 0) {
			data = p_new(
				ptxn->pool,
				struct push_notification_event_messagetrash_data, 1);
			data->trash = TRUE;
			push_notification_txn_msg_set_eventdata(
				ptxn, msg, ec, data);
		}
	}
}

/* Event definition */

extern struct push_notification_event push_notification_event_messagetrash;

struct push_notification_event push_notification_event_messagetrash = {
	.name = EVENT_NAME,
	.msg = {
		.debug_msg = push_notification_event_messagetrash_debug_msg,
	},
	.msg_triggers = {
		.flagchange = push_notification_event_messagetrash_event,
	},
};
