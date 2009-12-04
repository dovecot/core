#ifndef TRASH_PLUGIN_H
#define TRASH_PLUGIN_H

extern const char *trash_plugin_dependencies[];

void trash_plugin_init(struct module *module);
void trash_plugin_deinit(void);

#endif
