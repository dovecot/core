#ifndef REPLICATION_PLUGIN_H
#define REPLICATION_PLUGIN_H

extern const char *replication_plugin_dependencies[];

void replication_plugin_init(struct module *module);
void replication_plugin_deinit(void);

#endif
