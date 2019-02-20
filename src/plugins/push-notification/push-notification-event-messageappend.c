/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "istream.h"
#include "iso8601-date.h"
#include "mail-storage.h"

#include <time.h>

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-message-common.h"
#include "push-notification-event-messageappend.h"
#include "push-notification-txn-msg.h"


#define EVENT_NAME "MessageAppend"

static struct push_notification_event_messageappend_config default_config;


static void *push_notification_event_messageappend_default_config(void)
{
    i_zero(&default_config);

    return &default_config;
}

static void push_notification_event_messageappend_debug_msg
(struct push_notification_txn_event *event)
{
    struct push_notification_event_messageappend_data *data = event->data;
    struct tm *tm;

    if (data->date != -1) {
        tm = gmtime(&data->date);
        i_debug("%s: Date [%s]", EVENT_NAME,
                iso8601_date_create_tm(tm, data->date_tz));
    }

    if (data->from != NULL) {
        i_debug("%s: From [%s]", EVENT_NAME, data->from);
    }

    if (data->snippet != NULL) {
        i_debug("%s: Snippet [%s]", EVENT_NAME, data->snippet);
    }

    if (data->subject != NULL) {
        i_debug("%s: Subject [%s]", EVENT_NAME, data->subject);
    }

    if (data->to != NULL) {
        i_debug("%s: To [%s]", EVENT_NAME, data->to);
    }
}

static void
push_notification_event_messageappend_event(struct push_notification_txn *ptxn,
                                            struct push_notification_event_config *ec,
                                            struct push_notification_txn_msg *msg,
                                            struct mail *mail)
{
    struct push_notification_event_messageappend_config *config =
        (struct push_notification_event_messageappend_config *)ec->config;
    struct push_notification_event_messageappend_data *data;
    const char *value;
    time_t date;
    int tz;

    if (config->flags == 0) {
        return;
    }

    data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
    if (data == NULL) {
        data = p_new(ptxn->pool,
                     struct push_notification_event_messageappend_data, 1);
        data->date = -1;
        push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
    }

    if ((data->to == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_TO) != 0 &&
        (mail_get_first_header(mail, "To", &value) >= 0)) {
        data->to = p_strdup(ptxn->pool, value);
    }

    if ((data->from == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_FROM) != 0 &&
        (mail_get_first_header(mail, "From", &value) >= 0)) {
        data->from = p_strdup(ptxn->pool, value);
    }

    if ((data->subject == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT) != 0 &&
        (mail_get_first_header(mail, "Subject", &value) >= 0)) {
        data->subject = p_strdup(ptxn->pool, value);
    }

    if ((data->snippet == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET) != 0 &&
        (mail_get_special(mail, MAIL_FETCH_BODY_SNIPPET, &value) >= 0)) {
        /* [0] contains the snippet algorithm, skip over it */
        i_assert(value[0] != '\0');
        data->snippet = p_strdup(ptxn->pool, value + 1);
    }

    if ((data->date == -1) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_HDR_DATE) != 0 &&
        (mail_get_date(mail, &date, &tz) >= 0)) {
        data->date = date;
        data->date_tz = tz;
    }

    if (!data->flags_set &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_FLAGS) != 0) {
        data->flags = mail_get_flags(mail);
        data->flags_set = TRUE;
    }

    if ((data->keywords == NULL) &&
        (config->flags & PUSH_NOTIFICATION_MESSAGE_KEYWORDS) != 0) {
        const char *const *mail_kws = mail_get_keywords(mail);
        ARRAY_TYPE(const_string) kws;
        p_array_init(&kws, ptxn->pool, 2);
        for (;*mail_kws != NULL; mail_kws++) {
           value = p_strdup(ptxn->pool, *mail_kws);
           array_append(&kws, &value, 1);
        }
        array_append_zero(&kws);
        data->keywords = array_idx(&kws, 0);
    }
}


/* Event definition */

extern struct push_notification_event push_notification_event_messageappend;

struct push_notification_event push_notification_event_messageappend = {
    .name = EVENT_NAME,
    .init = {
        .default_config = push_notification_event_messageappend_default_config
    },
    .msg = {
        .debug_msg = push_notification_event_messageappend_debug_msg
    },
    .msg_triggers = {
        .append = push_notification_event_messageappend_event
    }
};
