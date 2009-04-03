/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "quota.h"
#include "quota-plugin.h"

#include <stdlib.h>

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

void (*quota_next_hook_mail_user_created)(struct mail_user *user);
void (*quota_next_hook_mail_storage_created)(struct mail_storage *storage);
void (*quota_next_hook_mailbox_list_created)(struct mailbox_list *list);

const char *quota_plugin_version = PACKAGE_VERSION;

void quota_plugin_init(void)
{
	quota_next_hook_mail_user_created = hook_mail_user_created;
	hook_mail_user_created = quota_mail_user_created;

	quota_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = quota_mail_storage_created;

	quota_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = quota_mailbox_list_created;
}

void quota_plugin_deinit(void)
{
	hook_mail_user_created = quota_next_hook_mail_user_created;
	hook_mail_storage_created = quota_next_hook_mail_storage_created;
	hook_mailbox_list_created = quota_next_hook_mailbox_list_created;
}
