/* Copyright (C) 2007 Timo Sirainen, LGPLv2.1 */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "autocreate-plugin.h"

#include <stdlib.h>

const char *autocreate_plugin_version = PACKAGE_VERSION;

static void (*autocreate_next_hook_mail_namespaces_created)
	(struct mail_namespace *ns);

static void autocreate_mailboxes(struct mail_storage *storage)
{
	char env_name[20];
	const char *env;
	unsigned int i;

	i = 1;
	env = getenv("AUTOCREATE");
	while (env != NULL) {
		(void)mail_storage_mailbox_create(storage, env, FALSE);
		i_snprintf(env_name, sizeof(env_name), "AUTOCREATE%d", ++i);
		env = getenv(env_name);
	}
}

static void autosubscribe_mailboxes(struct mailbox_list *list)
{
	char env_name[20];
	const char *env;
	unsigned int i;

	i = 1;
	env = getenv("AUTOSUBSCRIBE");
	while (env != NULL) {
		(void)mailbox_list_set_subscribed(list, env, TRUE);
		i_snprintf(env_name, sizeof(env_name), "AUTOSUBSCRIBE%d", ++i);
		env = getenv(env_name);
	}
}

static void autocreate_mail_namespaces_created(struct mail_namespace *ns)
{
	if (autocreate_next_hook_mail_namespaces_created != NULL)
		autocreate_next_hook_mail_namespaces_created(ns);

	for (; ns != NULL; ns = ns->next) {
		if (ns->type == NAMESPACE_PRIVATE) {
			autocreate_mailboxes(ns->storage);
			autosubscribe_mailboxes(ns->list);
			break;
		}
	}
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
