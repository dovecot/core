/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-hooks.h"
#include "mailbox-list-private.h"
#include "listescape-plugin.h"

#define DEFAULT_ESCAPE_CHAR '\\'

const char *listescape_plugin_version = DOVECOT_ABI_VERSION;

static void listescape_mailbox_list_created(struct mailbox_list *list)
{
	const char *env;

	if (list->set.escape_char == '\0') {
		env = mail_user_plugin_getenv(list->ns->user, "listescape_char");
		list->set.escape_char = env != NULL && *env != '\0' ?
			env[0] : DEFAULT_ESCAPE_CHAR;
	}
}

static struct mail_storage_hooks listescape_mail_storage_hooks = {
	.mailbox_list_created = listescape_mailbox_list_created
};

void listescape_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &listescape_mail_storage_hooks);
}

void listescape_plugin_deinit(void)
{
	mail_storage_hooks_remove(&listescape_mail_storage_hooks);
}
