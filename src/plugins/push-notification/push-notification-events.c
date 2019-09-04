/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"


ARRAY_TYPE(push_notification_event) push_notification_events;

ARRAY_TYPE(push_notification_event) *push_notification_get_events(void)
{
	return &push_notification_events;
}

static bool
push_notification_event_find(const char *name, unsigned int *idx_r)
{
    unsigned int count, i;
    const struct push_notification_event *const *events;

    events = array_get(&push_notification_events, &count);
    for (i = 0; i < count; i++) {
        if (strcasecmp(events[i]->name, name) == 0) {
            *idx_r = i;
            return TRUE;
        }
    }

    return FALSE;
}

static const struct push_notification_event *
push_notification_event_find_class(const char *driver)
{
    const struct push_notification_event *const *class_p;
    unsigned int idx;

    if (!push_notification_event_find(driver, &idx)) {
        return NULL;
    }

    class_p = array_idx(&push_notification_events, idx);

    return *class_p;
}

void
push_notification_event_init(struct push_notification_driver_txn *dtxn,
                             const char *event_name, void *config)
{
    const struct push_notification_event *event;
    struct push_notification_event_config *ec;

    if (!array_is_created(&dtxn->ptxn->events)) {
        p_array_init(&dtxn->ptxn->events, dtxn->ptxn->pool, 4);
    }

    event = push_notification_event_find_class(event_name);
    if (event != NULL) {
        if ((config == NULL) &&
            (event->init.default_config != NULL)) {
            config = event->init.default_config();
        }

        ec = p_new(dtxn->ptxn->pool, struct push_notification_event_config, 1);
        ec->config = config;
        ec->event = event;

        array_push_back(&dtxn->ptxn->events, &ec);
    }
}

void push_notification_event_register
(const struct push_notification_event *event)
{
    unsigned int idx;

    if (!array_is_created(&push_notification_events)) {
        i_array_init(&push_notification_events, 16);
    }

    if (push_notification_event_find(event->name, &idx)) {
        i_panic("push_notification_event_register(%s): duplicate event",
                event->name);
    }

    array_push_back(&push_notification_events, &event);
}

void push_notification_event_unregister
(const struct push_notification_event *event)
{
    unsigned int idx;

    if (!push_notification_event_find(event->name, &idx)) {
        i_panic("push_notification_event_register(%s): unknown event",
                event->name);
    }

    if (array_is_created(&push_notification_events)) {
        array_delete(&push_notification_events, idx, 1);

        if (array_is_empty(&push_notification_events)) {
            array_free(&push_notification_events);
        }
    }
}
