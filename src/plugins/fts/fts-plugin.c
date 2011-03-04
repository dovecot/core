/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-hooks.h"
#include "fts-plugin.h"

#include <stdlib.h>

const char *fts_plugin_version = DOVECOT_VERSION;

static struct mail_storage_hooks fts_mail_storage_hooks = {
	.mailbox_allocated = fts_mailbox_allocated,
	.mail_allocated = fts_mail_allocated
};

void fts_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &fts_mail_storage_hooks);
}

void fts_plugin_deinit(void)
{
	mail_storage_hooks_remove(&fts_mail_storage_hooks);
}
