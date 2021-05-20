#ifndef IMAP_ACL_PLUGIN_H
#define IMAP_ACL_PLUGIN_H

extern const char *imap_acl_plugin_dependencies[];
extern const char imap_acl_plugin_binary_dependency[];

extern MODULE_CONTEXT_DEFINE(imap_acl_storage_module, &mail_storage_module_register);

void imap_acl_plugin_init(struct module *module);
void imap_acl_plugin_deinit(void);

#endif
