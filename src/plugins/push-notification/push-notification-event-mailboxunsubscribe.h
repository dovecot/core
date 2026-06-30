/* Copyright (c) Dovecot authors, see top-level COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MAILBOXUNSUBSCRIBE_H
#define PUSH_NOTIFICATION_EVENT_MAILBOXUNSUBSCRIBE_H

struct push_notification_event_mailboxunsubscribe_data {
	/* Can only be FALSE. */
	bool subscribe;
};

#endif

