/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_PLUGIN_H
#define PUSH_NOTIFICATION_PLUGIN_H

extern const char *push_notification_plugin_dependencies[];
extern struct event_category event_category_push_notification;

struct module;

void push_notification_plugin_init(struct module *module);
void push_notification_plugin_deinit(void);

#endif
