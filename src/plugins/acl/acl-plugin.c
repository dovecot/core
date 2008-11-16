/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "acl-api.h"
#include "acl-lookup-dict.h"
#include "acl-plugin.h"

#include <stdlib.h>

void (*acl_next_hook_mail_storage_created)(struct mail_storage *storage);
void (*acl_next_hook_mailbox_list_created)(struct mailbox_list *list);
void (*acl_next_hook_mail_user_created)(struct mail_user *user);

const char *acl_plugin_version = PACKAGE_VERSION;

void acl_plugin_init(void)
{
	if (getenv("ACL") != NULL) {
		acl_next_hook_mail_storage_created =
			hook_mail_storage_created;
		hook_mail_storage_created = acl_mail_storage_created;

		acl_next_hook_mailbox_list_created = hook_mailbox_list_created;
		hook_mailbox_list_created = acl_mailbox_list_created;

		acl_next_hook_mail_user_created = hook_mail_user_created;
		hook_mail_user_created = acl_mail_user_created;

		acl_lookup_dicts_init();
	} else {
		if (getenv("DEBUG") != NULL)
			i_info("acl: No acl setting - ACLs are disabled");
	}
}

void acl_plugin_deinit(void)
{
	if (acl_next_hook_mail_storage_created != NULL) {
		acl_lookup_dicts_deinit();
		hook_mail_storage_created = acl_next_hook_mail_storage_created;
		hook_mailbox_list_created = acl_next_hook_mailbox_list_created;
		hook_mail_user_created = acl_next_hook_mail_user_created;
	}
}
