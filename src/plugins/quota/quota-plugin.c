/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "mail-storage.h"
#include "quota.h"
#include "quota-plugin.h"

#include <stdlib.h>

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

void (*quota_next_hook_mail_storage_created)(struct mail_storage *storage);
struct quota *quota = NULL;

void quota_plugin_init(void)
{
	const char *env;

	env = getenv("QUOTA");
	quota = env == NULL ? NULL : quota_init(env);

	if (quota != NULL) {
		quota_next_hook_mail_storage_created =
			hook_mail_storage_created;
		hook_mail_storage_created = quota_mail_storage_created;
	}
}

void quota_plugin_deinit(void)
{
	if (quota != NULL) {
		hook_mail_storage_created =
			quota_next_hook_mail_storage_created;
		quota_deinit(quota);
	}
}
