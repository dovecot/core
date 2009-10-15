/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "fts-plugin.h"

#include <stdlib.h>

const char *fts_plugin_version = PACKAGE_VERSION;

void (*fts_next_hook_mailbox_allocated)(struct mailbox *box);

void fts_plugin_init(void)
{
	fts_next_hook_mailbox_allocated = hook_mailbox_allocated;
	hook_mailbox_allocated = fts_mailbox_allocated;
}

void fts_plugin_deinit(void)
{
	hook_mailbox_allocated = fts_next_hook_mailbox_allocated;
}
