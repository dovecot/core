/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MAILBOXUNSUBSCRIBE_H
#define PUSH_NOTIFICATION_EVENT_MAILBOXUNSUBSCRIBE_H


struct push_notification_event_mailboxunsubscribe_data {
    /* Can only be false. */
    bool subscribe;
};


#endif /* PUSH_NOTIFICATION_EVENT_MAILBOXUNSUBSCRIBE_H */

