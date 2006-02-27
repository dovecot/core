/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "mail-storage.h"
#include "acl-api.h"
#include "acl-plugin.h"

#include <stdlib.h>

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

void (*acl_next_hook_mail_storage_created)(struct mail_storage *storage);

void acl_plugin_init(void)
{
	if (getenv("ACL") != NULL) {
		acl_next_hook_mail_storage_created =
			hook_mail_storage_created;
		hook_mail_storage_created = acl_mail_storage_created;
	}
}

void acl_plugin_deinit(void)
{
	if (acl_next_hook_mail_storage_created != NULL) {
		hook_mail_storage_created =
			acl_next_hook_mail_storage_created;
	}
}
