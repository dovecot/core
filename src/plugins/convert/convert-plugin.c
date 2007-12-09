/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "convert-storage.h"
#include "convert-plugin.h"

#include <stdlib.h>

const char *convert_plugin_version = PACKAGE_VERSION;

static void (*convert_next_hook_mail_namespaces_created)
	(struct mail_namespace *namespaces);

static void
convert_hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	const char *convert_mail, *str;
	struct convert_settings set;

	convert_mail = getenv("CONVERT_MAIL");
	if (convert_mail == NULL)
		return;

	memset(&set, 0, sizeof(set));
	set.user = getenv("USER");
	if (set.user == NULL)
		i_fatal("convert plugin: USER unset");
	set.home = getenv("HOME");
	if (set.home == NULL)
		i_fatal("convert plugin: HOME unset");

	set.skip_broken_mailboxes =
		getenv("CONVERT_SKIP_BROKEN_MAILBOXES") != NULL;
	set.skip_dotdirs = getenv("CONVERT_SKIP_DOTDIRS") != NULL;

	str = getenv("CONVERT_ALT_HIERARCHY_CHAR");
	set.alt_hierarchy_char = str != NULL && *str != '\0' ? *str : '_';

	if (convert_storage(convert_mail, namespaces, &set) < 0)
		i_fatal("Mailbox conversion failed, exiting");
}

void convert_plugin_init(void)
{
	convert_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created = convert_hook_mail_namespaces_created;
}

void convert_plugin_deinit(void)
{
	hook_mail_namespaces_created =
		convert_next_hook_mail_namespaces_created;
}
