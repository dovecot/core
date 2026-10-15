#ifndef QUOTA_STATUS_PLUGIN_H
#define QUOTA_STATUS_PLUGIN_H

struct module;

extern const char *quota_status_plugin_dependencies[];
extern const char quota_status_plugin_binary_dependency[];

void quota_status_plugin_init(struct module *module);
void quota_status_plugin_deinit(void);

#endif
