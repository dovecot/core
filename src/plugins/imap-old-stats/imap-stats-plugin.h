#ifndef IMAP_STATS_PLUGIN_H
#define IMAP_STATS_PLUGIN_H

struct module;

extern const char *imap_stats_plugin_dependencies[];
extern const char imap_stats_plugin_binary_dependency[];

void imap_stats_plugin_init(struct module *module);
void imap_stats_plugin_deinit(void);

#endif
