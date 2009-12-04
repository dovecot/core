#ifndef MAIL_LOG_PLUGIN_H
#define MAIL_LOG_PLUGIN_H

extern const char *mail_log_plugin_dependencies[];

void mail_log_plugin_init(struct module *module);
void mail_log_plugin_deinit(void);

#endif
