/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "push-notification-events.h"
#include "push-notification-events-rfc5423.h"

/* These are the RFC 5423 Mail Store Events currently handled within the core
   push-notification code.
  
   @todo: These events are not currently handled:
     - Login
     - Logout
     - QuotaExceed
     - Quota Within
 */
extern struct push_notification_event push_notification_event_flagsclear;
extern struct push_notification_event push_notification_event_flagsset;
extern struct push_notification_event push_notification_event_mailboxcreate;
extern struct push_notification_event push_notification_event_mailboxdelete;
extern struct push_notification_event push_notification_event_mailboxrename;
extern struct push_notification_event push_notification_event_mailboxsubscribe;
extern struct push_notification_event push_notification_event_mailboxunsubscribe;
extern struct push_notification_event push_notification_event_messageappend;
extern struct push_notification_event push_notification_event_messageexpunge;
extern struct push_notification_event push_notification_event_messagenew;
extern struct push_notification_event push_notification_event_messageread;
extern struct push_notification_event push_notification_event_messagetrash;

static struct push_notification_event *rfc5423_events[] = {
	&push_notification_event_flagsclear,
	&push_notification_event_flagsset,
	&push_notification_event_mailboxcreate,
	&push_notification_event_mailboxdelete,
	&push_notification_event_mailboxrename,
	&push_notification_event_mailboxsubscribe,
	&push_notification_event_mailboxunsubscribe,
	&push_notification_event_messageappend,
	&push_notification_event_messageexpunge,
	&push_notification_event_messagenew,
	&push_notification_event_messageread,
	&push_notification_event_messagetrash
};

void push_notification_event_register_rfc5423_events(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(rfc5423_events); i++)
		push_notification_event_register(rfc5423_events[i]);
}

void push_notification_event_unregister_rfc5423_events(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(rfc5423_events); i++)
		push_notification_event_unregister(rfc5423_events[i]);
}
