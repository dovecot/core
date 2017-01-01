/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_EVENT_MESSAGE_COMMON_H
#define PUSH_NOTIFICATION_EVENT_MESSAGE_COMMON_H


enum push_notification_event_message_flags {
    /* Header: From */
    PUSH_NOTIFICATION_MESSAGE_HDR_FROM = 0x01,
    /* Header: To */
    PUSH_NOTIFICATION_MESSAGE_HDR_TO = 0x02,
    /* Header: Subject */
    PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT = 0x04,
    /* Header: Date */
    PUSH_NOTIFICATION_MESSAGE_HDR_DATE = 0x08,
    /* Body: Snippet */
    PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET = 0x10
};


#endif	/* PUSH_NOTIFICATION_EVENT_MESSAGE_COMMON_H */

