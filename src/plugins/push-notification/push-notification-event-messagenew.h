/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGENEW_H
#define PUSH_NOTIFICATION_EVENT_MESSAGENEW_H


#include "push-notification-event-message-common.h"


struct push_notification_event_messagenew_config {
    enum push_notification_event_message_flags flags;
};

struct push_notification_event_messagenew_data {
    /* PUSH_NOTIFICATION_MESSAGE_HDR_FROM */
    const char *from;
    /* PUSH_NOTIFICATION_MESSAGE_HDR_TO */
    const char *to;
    /* PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT */
    const char *subject;
    /* PUSH_NOTIFICATION_MESSAGE_HDR_DATE */
    time_t date;
    int date_tz;
    /* PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET */
    const char *snippet;
    /* PUSH_NOTIFICATION_MESSAGE_FLAGS */
    bool flags_set;
    enum mail_flags flags;
    /* PUSH_NOTIFICATION_MESSAGE_KEYWORDS */
    const char *const *keywords;
};


#endif	/* PUSH_NOTIFICATION_EVENT_MESSAGENEW_H */

