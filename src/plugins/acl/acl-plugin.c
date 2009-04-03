/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "acl-api.h"
#include "acl-plugin.h"

#include <stdlib.h>

void (*acl_next_hook_mail_storage_created)(struct mail_storage *storage);
void (*acl_next_hook_mailbox_list_created)(struct mailbox_list *list);
void (*acl_next_hook_mail_user_created)(struct mail_user *user);

const char *acl_plugin_version = PACKAGE_VERSION;

void acl_plugin_init(void)
{
	acl_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = acl_mail_storage_created;

	acl_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = acl_mailbox_list_created;

	acl_next_hook_mail_user_created = hook_mail_user_created;
	hook_mail_user_created = acl_mail_user_created;
}

void acl_plugin_deinit(void)
{
	hook_mail_storage_created = acl_next_hook_mail_storage_created;
	hook_mailbox_list_created = acl_next_hook_mailbox_list_created;
	hook_mail_user_created = acl_next_hook_mail_user_created;
}
