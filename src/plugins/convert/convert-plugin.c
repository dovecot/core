/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "convert-storage.h"
#include "convert-plugin.h"

#include <stdlib.h>

const char *convert_plugin_version = PACKAGE_VERSION;

static void (*convert_next_hook_mail_namespaces_created)
	(struct mail_namespace *namespaces);

static void convert_mail_storage(struct mail_namespace *namespaces,
				 const char *convert_mail)
{
	const char *str;
	struct convert_settings set;

	memset(&set, 0, sizeof(set));
	if (mail_user_get_home(namespaces->user, &str) <= 0)
		i_fatal("convert plugin: HOME unset");

	set.skip_broken_mailboxes =
		getenv("CONVERT_SKIP_BROKEN_MAILBOXES") != NULL;
	set.skip_dotdirs = getenv("CONVERT_SKIP_DOTDIRS") != NULL;

	str = getenv("CONVERT_ALT_HIERARCHY_CHAR");
	set.alt_hierarchy_char = str != NULL && *str != '\0' ? *str : '_';

	if (convert_storage(convert_mail, namespaces, &set) < 0)
		i_fatal("Mailbox conversion failed, exiting");
}

static void
convert_hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	const char *convert_mail;

	convert_mail = getenv("CONVERT_MAIL");
	if (convert_mail != NULL)
		convert_mail_storage(namespaces, convert_mail);
	else if (getenv("DEBUG") != NULL)
		i_info("convert: No convert_mail setting - plugin disabled");

	if (convert_next_hook_mail_namespaces_created != NULL)
		convert_next_hook_mail_namespaces_created(namespaces);
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
