#ifndef QUOTA_PLUGIN_H
#define QUOTA_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"

struct module;
struct mailbox;
struct mailbox_list;
struct mail;

#define QUOTA_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_user_module)

struct quota_user {
	union mail_user_module_context module_ctx;

	struct quota *quota;
};

struct mail_storage;

extern MODULE_CONTEXT_DEFINE(quota_user_module, &mail_user_module_register);

void quota_mail_user_created(struct mail_user *user);
void quota_mailbox_list_created(struct mailbox_list *list);
void quota_mail_namespaces_created(struct mail_namespace *namespaces);
void quota_mailbox_allocated(struct mailbox *box);
void quota_mail_allocated(struct mail *mail);

void quota_plugin_init(struct module *module);
void quota_plugin_deinit(void);

#endif
