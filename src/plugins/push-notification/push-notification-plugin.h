/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_PLUGIN_H
#define PUSH_NOTIFICATION_PLUGIN_H

extern const char *push_notification_plugin_dependencies[];

struct module;

void push_notification_plugin_init(struct module *module);
void push_notification_plugin_deinit(void);

#endif
