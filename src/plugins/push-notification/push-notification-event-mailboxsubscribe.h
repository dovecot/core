/* Copyright (c) Dovecot authors, see top-level COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MAILBOXSUBSCRIBE_H
#define PUSH_NOTIFICATION_EVENT_MAILBOXSUBSCRIBE_H

struct push_notification_event_mailboxsubscribe_data {
	/* Can only be TRUE. */
	bool subscribe;
};

#endif

