/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-types.h"

#include "push-notification-drivers.h"
#include "push-notification-event-messageexpunge.h"
#include "push-notification-events.h"
#include "push-notification-txn-msg.h"

#define EVENT_NAME "MessageExpunge"

static void
push_notification_event_messageexpunge_debug_msg(
	struct push_notification_txn_event *event)
{
	struct push_notification_event_messageexpunge_data *data = event->data;

	if (data != NULL)
		i_debug("%s: Message was expunged", EVENT_NAME);
}

static void
push_notification_event_messageexpunge_event(
	struct push_notification_txn *ptxn,
	struct push_notification_event_config *ec,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_event_messageexpunge_data *data;

	data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
	if (data == NULL) {
		data = p_new(ptxn->pool,
			     struct push_notification_event_messageexpunge_data, 1);
		data->expunge = TRUE;
		push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
	}
}

/* Event definition */

extern struct push_notification_event push_notification_event_messageexpunge;

struct push_notification_event push_notification_event_messageexpunge = {
	.name = EVENT_NAME,
	.msg = {
		.debug_msg = push_notification_event_messageexpunge_debug_msg,
	},
	.msg_triggers = {
		.expunge = push_notification_event_messageexpunge_event,
	},
};
