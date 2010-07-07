#ifndef IMAP_ACL_PLUGIN_H
#define IMAP_ACL_PLUGIN_H

extern const char *imap_acl_plugin_dependencies[];
extern const char imap_acl_plugin_binary_dependency[];

void imap_acl_plugin_init(struct module *module);
void imap_acl_plugin_deinit(void);

#endif
