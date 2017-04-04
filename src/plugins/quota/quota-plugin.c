/* Copyright (c) 2005-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "quota-plugin.h"

void quota_backends_register(void);
void quota_backends_unregister(void);

const char *quota_plugin_version = DOVECOT_ABI_VERSION;

static struct mail_storage_hooks quota_mail_storage_hooks = {
	.mail_user_created = quota_mail_user_created,
	.mail_namespaces_created = quota_mail_namespaces_created,
	.mailbox_list_created = quota_mailbox_list_created,
	.mailbox_allocated = quota_mailbox_allocated,
	.mail_allocated = quota_mail_allocated
};

void quota_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &quota_mail_storage_hooks);
	quota_backends_register();
}

void quota_plugin_deinit(void)
{
	mail_storage_hooks_remove(&quota_mail_storage_hooks);
	quota_backends_unregister();
}
