#ifndef __ACL_PLUGIN_H
#define __ACL_PLUGIN_H

#include "mail-storage-private.h"

#define ACL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_storage_module)

enum acl_storage_rights {
	ACL_STORAGE_RIGHT_LOOKUP,
	ACL_STORAGE_RIGHT_READ,
	ACL_STORAGE_RIGHT_WRITE,
	ACL_STORAGE_RIGHT_WRITE_SEEN,
	ACL_STORAGE_RIGHT_WRITE_DELETED,
	ACL_STORAGE_RIGHT_INSERT,
	ACL_STORAGE_RIGHT_EXPUNGE,
	ACL_STORAGE_RIGHT_CREATE,
	ACL_STORAGE_RIGHT_DELETE,
	ACL_STORAGE_RIGHT_ADMIN,

	ACL_STORAGE_RIGHT_COUNT
};

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
				      const char *name,
				      unsigned int acl_storage_right_idx,
				      bool *can_see_r);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list);
const char *acl_mailbox_list_get_parent_mailbox_name(struct mailbox_list *list,
						     const char *name);

void acl_plugin_init(void);
void acl_plugin_deinit(void);

#endif
