/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage.h"
#include "mail-types.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-flagsclear.h"
#include "push-notification-txn-msg.h"


#define EVENT_NAME "FlagsClear"

static struct push_notification_event_flagsclear_config default_config;


static void *push_notification_event_flagsclear_default_config(void)
{
    i_zero(&default_config);

    return &default_config;
}

static void push_notification_event_flagsclear_debug_msg
(struct push_notification_txn_event *event)
{
    struct push_notification_event_flagsclear_data *data = event->data;
    const char *const *keyword;

    if ((data->flags_clear & MAIL_ANSWERED) != 0) {
        i_debug("%s: Answered flag cleared", EVENT_NAME);
    }
    if ((data->flags_clear & MAIL_FLAGGED) != 0) {
        i_debug("%s: Flagged flag cleared", EVENT_NAME);
    }
    if ((data->flags_clear & MAIL_DELETED) != 0) {
        i_debug("%s: Deleted flag cleared", EVENT_NAME);
    }
    if ((data->flags_clear & MAIL_SEEN) != 0) {
        i_debug("%s: Seen flag cleared", EVENT_NAME);
    }
    if ((data->flags_clear & MAIL_DRAFT) != 0) {
        i_debug("%s: Draft flag cleared", EVENT_NAME);
    }

    array_foreach(&data->keywords_clear, keyword) {
        i_debug("%s: Keyword clear [%s]", EVENT_NAME, *keyword);
    }
}

static struct push_notification_event_flagsclear_data *
push_notification_event_flagsclear_get_data(struct push_notification_txn *ptxn,
                                            struct push_notification_txn_msg *msg,
                                            struct push_notification_event_config *ec)
{
    struct push_notification_event_flagsclear_config *config =
        (struct push_notification_event_flagsclear_config *)ec->config;
    struct push_notification_event_flagsclear_data *data;

    data = push_notification_txn_msg_get_eventdata(msg, EVENT_NAME);
    if (data == NULL) {
        data = p_new(ptxn->pool,
                     struct push_notification_event_flagsclear_data, 1);
        data->flags_clear = 0;
        data->flags_old = 0;
        p_array_init(&data->keywords_clear, ptxn->pool, 4);
        if (config->store_old == TRUE) {
            p_array_init(&data->keywords_old, ptxn->pool, 4);
        }

        push_notification_txn_msg_set_eventdata(ptxn, msg, ec, data);
    }

    return data;
}

static void push_notification_event_flagsclear_flags_event(
    struct push_notification_txn *ptxn,
    struct push_notification_event_config *ec,
    struct push_notification_txn_msg *msg,
    struct mail *mail,
    enum mail_flags old_flags)
{
    struct push_notification_event_flagsclear_config *config =
        (struct push_notification_event_flagsclear_config *)ec->config;
    struct push_notification_event_flagsclear_data *data;
    enum mail_flags flag_check_always[] = {
        MAIL_ANSWERED,
        MAIL_DELETED,
        MAIL_DRAFT,
        MAIL_FLAGGED,
        MAIL_SEEN
    };
    enum mail_flags flags;
    unsigned int i;

    data = push_notification_event_flagsclear_get_data(ptxn, msg, ec);
    flags = mail_get_flags(mail);

    for (i = 0; i < N_ELEMENTS(flag_check_always); i++) {
        if ((flags & flag_check_always[i]) == 0 &&
            (old_flags & flag_check_always[i]) != 0) {
            data->flags_clear |= flag_check_always[i];
        }
    }

    if (config->store_old == TRUE) {
        data->flags_old = old_flags;
    }
}

static void push_notification_event_flagsclear_keywords_event(
    struct push_notification_txn *ptxn,
    struct push_notification_event_config *ec,
    struct push_notification_txn_msg *msg,
    struct mail *mail,
    const char *const *old_keywords)
{
    struct push_notification_event_flagsclear_config *config =
        (struct push_notification_event_flagsclear_config *)ec->config;
    struct push_notification_event_flagsclear_data *data;
    const char *const *keywords, *const *kp, *ok;

    data = push_notification_event_flagsclear_get_data(ptxn, msg, ec);
    keywords = mail_get_keywords(mail);

    for (; *old_keywords != NULL; old_keywords++) {
        for (kp = keywords; *kp != NULL; kp++) {
            if (strcmp(*old_keywords, *kp) == 0) {
                break;
            }
        }

        if (*kp == NULL) {
            ok = p_strdup(ptxn->pool, *old_keywords);
            array_push_back(&data->keywords_clear, &ok);
        }

        if (config->store_old == TRUE) {
            ok = p_strdup(ptxn->pool, *old_keywords);
            array_push_back(&data->keywords_old, &ok);
        }
    }
}

static void push_notification_event_flagsclear_free_msg(
    struct push_notification_txn_event *event)
{
    struct push_notification_event_flagsclear_data *data = event->data;

    if (array_is_created(&data->keywords_clear)) {
        array_free(&data->keywords_clear);
    }
    if (array_is_created(&data->keywords_old)) {
        array_free(&data->keywords_old);
    }
}


/* Event definition */

extern struct push_notification_event push_notification_event_flagsclear;

struct push_notification_event push_notification_event_flagsclear = {
    .name = EVENT_NAME,
    .init = {
        .default_config = push_notification_event_flagsclear_default_config
    },
    .msg = {
        .debug_msg = push_notification_event_flagsclear_debug_msg,
        .free_msg = push_notification_event_flagsclear_free_msg
    },
    .msg_triggers = {
        .flagchange = push_notification_event_flagsclear_flags_event,
        .keywordchange = push_notification_event_flagsclear_keywords_event
    }
};
