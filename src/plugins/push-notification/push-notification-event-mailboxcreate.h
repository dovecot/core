/* Copyright (c) Dovecot authors, see top-level COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MAILBOXCREATE_H
#define PUSH_NOTIFICATION_EVENT_MAILBOXCREATE_H

struct push_notification_event_mailboxcreate_data {
	/* RFC 5423 [4.4]: UIDVALIDITY required for create event. */
	uint32_t uid_validity;
};

#endif

