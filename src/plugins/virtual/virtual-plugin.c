/* Copyright (c) 2008-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "virtual-storage.h"
#include "virtual-plugin.h"

const char *virtual_plugin_version = DOVECOT_ABI_VERSION;

static struct mail_storage_hooks acl_mail_storage_hooks = {
	.mailbox_allocated = virtual_backend_mailbox_allocated,
	.mailbox_opened = virtual_backend_mailbox_opened
};

void virtual_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_storage_class_register(&virtual_storage);
	mail_storage_hooks_add(module, &acl_mail_storage_hooks);
}

void virtual_plugin_deinit(void)
{
	mail_storage_class_unregister(&virtual_storage);
	mail_storage_hooks_remove(&acl_mail_storage_hooks);
}
