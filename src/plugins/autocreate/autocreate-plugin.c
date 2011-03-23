/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "mail-storage.h"
#include "mail-storage-hooks.h"
#include "mail-namespace.h"
#include "autocreate-plugin.h"

#include <stdlib.h>

const char *autocreate_plugin_version = DOVECOT_VERSION;

static void
autocreate_mailbox(struct mail_namespace *namespaces, const char *name)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *str;
	enum mail_error error;

	ns = mail_namespace_find(namespaces, &name);
	if (ns == NULL) {
		if (namespaces->mail_set->mail_debug)
			i_debug("autocreate: No namespace found for %s", name);
		return;
	}

	box = mailbox_alloc(ns->list, name, 0);
	if (mailbox_create(box, NULL, FALSE) < 0) {
		str = mail_storage_get_last_error(mailbox_get_storage(box),
						  &error);
		if (error != MAIL_ERROR_EXISTS && ns->mail_set->mail_debug) {
			i_debug("autocreate: Failed to create mailbox %s: %s",
				name, str);
		}
	}
	mailbox_free(&box);
}

static void autocreate_mailboxes(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = mail_user_plugin_getenv(user, "autocreate");
	while (name != NULL) {
		autocreate_mailbox(namespaces, name);

		i_snprintf(env_name, sizeof(env_name), "autocreate%d", ++i);
		name = mail_user_plugin_getenv(user, env_name);
	}
}

static void
autosubscribe_mailbox(struct mail_namespace *namespaces, const char *name)
{
	struct mail_namespace *ns;
	const char *str;
	enum mail_error error;

	ns = mail_namespace_find_subscribable(namespaces, &name);
	if (ns == NULL) {
		if (namespaces->mail_set->mail_debug)
			i_debug("autocreate: No namespace found for %s", name);
		return;
	}

	if (mailbox_list_set_subscribed(ns->list, name, TRUE) < 0) {
		str = mailbox_list_get_last_error(ns->list,
						  &error);
		if (error != MAIL_ERROR_EXISTS && ns->mail_set->mail_debug) {
			i_debug("autocreate: Failed to subscribe mailbox "
				"%s: %s", name, str);
		}
	}
}

static void autosubscribe_mailboxes(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = mail_user_plugin_getenv(user, "autosubscribe");
	while (name != NULL) {
		autosubscribe_mailbox(namespaces, name);

		i_snprintf(env_name, sizeof(env_name), "autosubscribe%d", ++i);
		name = mail_user_plugin_getenv(user, env_name);
	}
}

static void
autocreate_mail_namespaces_created(struct mail_namespace *namespaces)
{
	if (strcmp(master_service_get_name(master_service), "dsync") == 0) {
		/* kludge: disable autocreate plugin for dsync,
		   since it'll only make things worse. this is fixed more
		   nicely in v2.1 code. */
		return;
	}
	autocreate_mailboxes(namespaces);
	autosubscribe_mailboxes(namespaces);
}

static struct mail_storage_hooks autocreate_mail_storage_hooks = {
	.mail_namespaces_created = autocreate_mail_namespaces_created
};

void autocreate_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &autocreate_mail_storage_hooks);
}

void autocreate_plugin_deinit(void)
{
	mail_storage_hooks_remove(&autocreate_mail_storage_hooks);
}
