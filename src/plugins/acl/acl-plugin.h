#ifndef ACL_PLUGIN_H
#define ACL_PLUGIN_H

#include "mail-storage-private.h"
#include "acl-storage.h"

#define ACL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_storage_module)

struct acl_storage_rights_context {
	struct acl_backend *backend;
	unsigned int acl_storage_right_idx[ACL_STORAGE_RIGHT_COUNT];
};

struct acl_mail_storage {
	union mail_storage_module_context module_ctx;
	struct acl_storage_rights_context rights;
};

extern void (*acl_next_hook_mail_storage_created)
	(struct mail_storage *storage);
extern void (*acl_next_hook_mailbox_list_created)(struct mailbox_list *list);
extern MODULE_CONTEXT_DEFINE(acl_storage_module, &mail_storage_module_register);

void acl_mail_storage_created(struct mail_storage *storage);
void acl_mailbox_list_created(struct mailbox_list *list);

struct mailbox *acl_mailbox_open_box(struct mailbox *box);

void acl_storage_rights_ctx_init(struct acl_storage_rights_context *ctx,
				 struct acl_backend *backend);
int acl_storage_rights_ctx_have_right(struct acl_storage_rights_context *ctx,
				      const char *name, bool parent,
				      unsigned int acl_storage_right_idx,
				      bool *can_see_r);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list);

void acl_plugin_init(void);
void acl_plugin_deinit(void);

#endif
