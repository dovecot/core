/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "acl-api.h"
#include "acl-plugin.h"

#include <stdlib.h>

const char *acl_plugin_version = DOVECOT_VERSION;

static struct mail_storage_hooks acl_mail_storage_hooks = {
	.mail_user_created = acl_mail_user_created,
	.mailbox_list_created = acl_mailbox_list_created,
	.mail_namespace_storage_added = acl_mail_namespace_storage_added,
	.mailbox_allocated = acl_mailbox_allocated,
	.mail_allocated = acl_mail_allocated
};

void acl_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &acl_mail_storage_hooks);
}

void acl_plugin_deinit(void)
{
	mail_storage_hooks_remove(&acl_mail_storage_hooks);
}
