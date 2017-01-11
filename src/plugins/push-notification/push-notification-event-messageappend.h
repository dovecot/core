/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGEAPPEND_H
#define PUSH_NOTIFICATION_EVENT_MESSAGEAPPEND_H


struct push_notification_event_messageappend_config {
    enum push_notification_event_message_flags flags;
};

struct push_notification_event_messageappend_data {
    const char *from;
    const char *to;
    const char *subject;
    const char *snippet;
};


#endif	/* PUSH_NOTIFICATION_EVENT_MESSAGEAPPEND_H */

