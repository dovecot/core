/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-mailboxunsubscribe.h"
#include "push-notification-txn-mbox.h"

#define EVENT_NAME "MailboxUnsubscribe"

static void
push_notification_event_mailboxunsubscribe_debug_mbox(
	struct push_notification_txn_event *event ATTR_UNUSED)
{
	i_debug("%s: Mailbox was subscribed to", EVENT_NAME);
}

static void
push_notification_event_mailboxunsubscribe_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_mbox *mbox)
{
	struct push_notification_event_mailboxunsubscribe_data *data;

	data = p_new(ptxn->pool,
		     struct push_notification_event_mailboxunsubscribe_data, 1);
	data->subscribe = FALSE;

	push_notification_txn_mbox_set_eventdata(ptxn, mbox, ec, data);
}

/* Event definition */

extern struct push_notification_event push_notification_event_mailboxunsubscribe;

struct push_notification_event push_notification_event_mailboxunsubscribe = {
	.name = EVENT_NAME,
	.mbox = {
		.debug_mbox =
			push_notification_event_mailboxunsubscribe_debug_mbox,
	},
	.mbox_triggers = {
		.unsubscribe = push_notification_event_mailboxunsubscribe_event,
	},
};
