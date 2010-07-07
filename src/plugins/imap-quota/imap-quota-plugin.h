#ifndef IMAP_QUOTA_PLUGIN_H
#define IMAP_QUOTA_PLUGIN_H

struct module;

extern const char *imap_quota_plugin_dependencies[];
extern const char imap_quota_plugin_binary_dependency[];

void imap_quota_plugin_init(struct module *module);
void imap_quota_plugin_deinit(void);

#endif
