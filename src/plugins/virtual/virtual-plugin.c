/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "virtual-storage.h"
#include "virtual-plugin.h"

static void (*virtual_next_hook_mail_namespaces_created)
	(struct mail_namespace *namespaces);

const char *virtual_plugin_version = PACKAGE_VERSION;
struct mail_namespace *virtual_all_namespaces;

static void
virtual_hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	if (virtual_next_hook_mail_namespaces_created != NULL)
		virtual_next_hook_mail_namespaces_created(namespaces);

	/* FIXME: some day we should support multiple clients and this
	   global namespaces list doesn't work */
	virtual_all_namespaces = namespaces;
}

void virtual_plugin_init(void)
{
	mail_storage_class_register(&virtual_storage);

	virtual_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created = virtual_hook_mail_namespaces_created;
}

void virtual_plugin_deinit(void)
{
	mail_storage_class_unregister(&virtual_storage);

	hook_mail_namespaces_created =
		virtual_next_hook_mail_namespaces_created;
}
