/* Copyright (C) 2007 Timo Sirainen, LGPLv2.1 */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "autocreate-plugin.h"

#include <stdlib.h>

const char *autocreate_plugin_version = PACKAGE_VERSION;

static void (*autocreate_next_hook_mail_namespaces_created)
	(struct mail_namespace *ns);

static void autocreate_mailboxes(struct mail_namespace *namespaces)
{
	struct mail_namespace *ns;
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = getenv("AUTOCREATE");
	while (name != NULL) {
		ns = mail_namespace_find(namespaces, &name);
		if (ns != NULL) {
			(void)mail_storage_mailbox_create(ns->storage,
							  name, FALSE);
		}

		i_snprintf(env_name, sizeof(env_name), "AUTOCREATE%d", ++i);
		name = getenv(env_name);
	}
}

static void autosubscribe_mailboxes(struct mail_namespace *namespaces)
{
	struct mail_namespace *ns;
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = getenv("AUTOSUBSCRIBE");
	while (name != NULL) {
		ns = mail_namespace_find(namespaces, &name);
		if (ns != NULL)
			(void)mailbox_list_set_subscribed(ns->list, name, TRUE);

		i_snprintf(env_name, sizeof(env_name), "AUTOSUBSCRIBE%d", ++i);
		name = getenv(env_name);
	}
}

static void
autocreate_mail_namespaces_created(struct mail_namespace *namespaces)
{
	if (autocreate_next_hook_mail_namespaces_created != NULL)
		autocreate_next_hook_mail_namespaces_created(namespaces);

	autocreate_mailboxes(namespaces);
	autosubscribe_mailboxes(namespaces);
}

void autocreate_plugin_init(void)
{
	autocreate_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created = autocreate_mail_namespaces_created;
}

void autocreate_plugin_deinit(void)
{
	hook_mail_namespaces_created =
		autocreate_next_hook_mail_namespaces_created;
}
