/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "mail-storage-private.h"
#include "fts-plugin.h"

void (*fts_next_hook_mailbox_opened)(struct mailbox *box);

void fts_plugin_init(void)
{
	fts_next_hook_mailbox_opened = hook_mailbox_opened;
	hook_mailbox_opened = fts_mailbox_opened;
}

void fts_plugin_deinit(void)
{
	if (hook_mailbox_opened == fts_mailbox_opened)
		hook_mailbox_opened = fts_next_hook_mailbox_opened;
}
