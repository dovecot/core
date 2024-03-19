/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-hooks.h"
#include "lang-filter.h"
#include "lang-library.h"
#include "lang-tokenizer.h"
#include "fts-parser.h"
#include "fts-storage.h"
#include "fts-user.h"
#include "fts-plugin.h"

const char *fts_plugin_version = DOVECOT_ABI_VERSION;

static struct mail_storage_hooks fts_mail_storage_hooks = {
	.mail_user_created = fts_mail_user_created,
	.mail_namespaces_added = fts_mail_namespaces_added,
	.mailbox_list_created = fts_mailbox_list_created,
	.mailbox_allocated = fts_mailbox_allocated,
	.mail_allocated = fts_mail_allocated
};

void fts_plugin_init(struct module *module)
{
	lang_library_init();
	mail_storage_hooks_add(module, &fts_mail_storage_hooks);
}

void fts_plugin_deinit(void)
{
	lang_library_deinit();
	fts_parsers_unload();
	mail_storage_hooks_remove(&fts_mail_storage_hooks);
}
