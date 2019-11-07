/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "iso8601-date.h"
#include "istream.h"
#include "mail-storage.h"

#include <time.h>

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-message-common.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-txn-msg.h"


#define EVENT_NAME "MessageNew"

static struct push_notification_event_messagenew_config default_config;


static void *push_notification_event_messagenew_default_config(void)
{
    i_zero(&default_config);

    return &default_config;
}

static void push_notification_event_messagenew_debug_msg
(struct push_notification_txn_event *event)
{
    struct push_notification_event_messagenew_data *data = event->data;
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
push_notification_event_messagenew_event(struct push_notification_txn *ptxn,
                                         struct push_notification_event_config *ec,
                                         struct push_notification_txn_msg *msg,
                                         struct mail *mail)
{
    struct push_notification_event_messagenew_config *config =
        (struct push_notification_event_messagenew_config *)ec->config;
    struct push_notification_event_messagenew_data *data;

    if (config->flags == 0) {
        return;
    }

    data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
    if (data == NULL) {
        data = p_new(ptxn->pool,
                     struct push_notification_event_messagenew_data, 1);
        data->date = -1;

        push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
    }

    push_notification_message_fill(mail, ptxn->pool, config->flags,
				   &data->from, &data->to, &data->subject,
				   &data->date, &data->date_tz,
				   &data->message_id,
				   &data->flags, &data->flags_set,
				   &data->keywords,
				   &data->snippet);
}


/* Event definition */

struct push_notification_event push_notification_event_messagenew = {
    .name = EVENT_NAME,
    .init = {
        .default_config = push_notification_event_messagenew_default_config
    },
    .msg = {
        .debug_msg = push_notification_event_messagenew_debug_msg
    },
    .msg_triggers = {
        .save = push_notification_event_messagenew_event
    }
};
