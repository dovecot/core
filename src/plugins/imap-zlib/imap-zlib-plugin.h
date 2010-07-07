#ifndef IMAP_ZLIB_PLUGIN_H
#define IMAP_ZLIB_PLUGIN_H

struct module;

extern const char *imap_zlib_plugin_dependencies[];
extern const char imap_zlib_plugin_binary_dependency[];

void imap_zlib_plugin_init(struct module *module);
void imap_zlib_plugin_deinit(void);

#endif
