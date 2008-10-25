/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "fts-plugin.h"

#include <stdlib.h>

const char *fts_plugin_version = PACKAGE_VERSION;

void (*fts_next_hook_mailbox_opened)(struct mailbox *box);

void fts_plugin_init(void)
{
	if (getenv("FTS") != NULL) {
		fts_next_hook_mailbox_opened = hook_mailbox_opened;
		hook_mailbox_opened = fts_mailbox_opened;
	} else if (getenv("DEBUG") != NULL)
		i_info("fts: Missing fts setting, disabled");
}

void fts_plugin_deinit(void)
{
	if (hook_mailbox_opened == fts_mailbox_opened)
		hook_mailbox_opened = fts_next_hook_mailbox_opened;
}
