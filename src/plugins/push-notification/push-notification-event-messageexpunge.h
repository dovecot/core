/* Copyright (c) Dovecot authors, see top-level COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGEEXPUNGE_H
#define PUSH_NOTIFICATION_EVENT_MESSAGEEXPUNGE_H

struct push_notification_event_messageexpunge_data {
	/* Can only be TRUE. */
	bool expunge;
};

#endif

