#ifndef ACL_PLUGIN_H
#define ACL_PLUGIN_H

#include "mail-user.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "acl-storage.h"

#define ACL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_storage_module)
#define ACL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_mailbox_list_module)
#define ACL_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_user_module)

struct acl_user {
	union mail_user_module_context module_ctx;

	const char *master_user;
	const char *acl_env;
	const char *const *groups;

	struct acl_lookup_dict *acl_lookup_dict;
	time_t last_shared_add_check;
};

struct acl_storage_rights_context {
	struct acl_backend *backend;
	unsigned int acl_storage_right_idx[ACL_STORAGE_RIGHT_COUNT];
};

struct acl_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct acl_storage_rights_context rights;
};

extern MODULE_CONTEXT_DEFINE(acl_storage_module, &mail_storage_module_register);
extern MODULE_CONTEXT_DEFINE(acl_user_module, &mail_user_module_register);
extern MODULE_CONTEXT_DEFINE(acl_mailbox_list_module,
			     &mailbox_list_module_register);

void acl_mail_storage_created(struct mail_storage *storage);
void acl_mail_namespace_storage_added(struct mail_namespace *ns);
void acl_mail_user_created(struct mail_user *list);

struct mailbox *
acl_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		  const char *name, struct istream *input,
		  enum mailbox_flags flags);

struct acl_backend *acl_mailbox_list_get_backend(struct mailbox_list *list);
int acl_mailbox_list_have_right(struct mailbox_list *list, const char *name,
				bool parent, unsigned int acl_storage_right_idx,
				bool *can_see_r);

void acl_plugin_init(struct module *module);
void acl_plugin_deinit(void);

#endif
