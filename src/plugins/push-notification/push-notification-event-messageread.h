/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGEREAD_H
#define PUSH_NOTIFICATION_EVENT_MESSAGEREAD_H

struct push_notification_event_messageread_data {
	/* Can only be TRUE. */
	bool read;
};

#endif
