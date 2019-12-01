/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-mailboxrename.h"
#include "push-notification-txn-mbox.h"

#define EVENT_NAME "MailboxRename"

static void
push_notification_event_mailboxrename_debug_mbox(
	struct push_notification_txn_event *event)
{
	struct push_notification_event_mailboxrename_data *data = event->data;

	i_debug("%s: Mailbox was renamed (old name: %s)",
		EVENT_NAME, data->old_mbox);
}

static void
push_notification_event_mailboxrename_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_mbox *mbox, struct mailbox *old)
{
	struct push_notification_event_mailboxrename_data *data;

	data = p_new(ptxn->pool,
		     struct push_notification_event_mailboxrename_data, 1);
	data->old_mbox = mailbox_get_vname(old);

	push_notification_txn_mbox_set_eventdata(ptxn, mbox, ec, data);
}

/* Event definition */

extern struct push_notification_event push_notification_event_mailboxrename;

struct push_notification_event push_notification_event_mailboxrename = {
	.name = EVENT_NAME,
	.mbox = {
		.debug_mbox = push_notification_event_mailboxrename_debug_mbox,
	},
	.mbox_triggers = {
		.rename = push_notification_event_mailboxrename_event,
	},
};
