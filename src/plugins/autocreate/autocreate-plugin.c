/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

/* FIXME: this plugin is only for backwards compatibility. log a warning in
   v2.2 about this and in later versions remove completely */

#include "lib.h"
#include "array.h"
#include "unichar.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-hooks.h"
#include "autocreate-plugin.h"

static struct mailbox_settings *
mailbox_settings_find(struct mail_namespace *ns, const char *vname)
{
	struct mailbox_settings *const *box_set;

	array_foreach(&ns->set->mailboxes, box_set) {
		if (strcmp((*box_set)->name, vname) == 0)
			return *box_set;
	}
	return NULL;
}

static void
add_autobox(struct mail_user *user, const char *vname, bool subscriptions)
{
	struct mail_namespace *ns;
	struct mailbox_settings *set;
	struct mail_namespace_settings tmp_ns_set;

	if (!uni_utf8_str_is_valid(vname)) {
		i_error("autocreate: Mailbox name isn't valid UTF-8: %s",
			vname);
		return;
	}

	ns = mail_namespace_find(user->namespaces, vname);
	if ((ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		i_error("autocreate: No namespace found for mailbox: %s",
			vname);
		return;
	}

	if (array_is_created(&ns->set->mailboxes))
		tmp_ns_set.mailboxes = ns->set->mailboxes;
	else {
		p_array_init(&tmp_ns_set.mailboxes, user->pool, 16);
		/* work around ns->set being a const pointer. pretty ugly, but
		   this plugin is deprecated anyway. */
		memcpy((void *)&ns->set->mailboxes.arr, &tmp_ns_set.mailboxes.arr,
		       sizeof(ns->set->mailboxes.arr));
	}

	if (strncmp(vname, ns->prefix, ns->prefix_len) == 0)
		vname += ns->prefix_len;
	set = mailbox_settings_find(ns, vname);
	if (set == NULL) {
		set = p_new(user->pool, struct mailbox_settings, 1);
		set->name = p_strdup(user->pool, vname);
		set->autocreate = MAILBOX_SET_AUTO_NO;
		set->special_use = "";
		array_push_back(&tmp_ns_set.mailboxes, &set);
	}
	if (subscriptions)
		set->autocreate = MAILBOX_SET_AUTO_SUBSCRIBE;
	else if (strcmp(set->autocreate, MAILBOX_SET_AUTO_SUBSCRIBE) != 0)
		set->autocreate = MAILBOX_SET_AUTO_CREATE;
}

static void
read_autobox_settings(struct mail_user *user, const char *env_name_base,
		      bool subscriptions)
{
	const char *value;
	char env_name[strlen(env_name_base) + MAX_INT_STRLEN];
	unsigned int i = 1;

	value = mail_user_plugin_getenv(user, env_name_base);
	while (value != NULL) {
		add_autobox(user, value, subscriptions);

		if (i_snprintf(env_name, sizeof(env_name), "%s%u",
			       env_name_base, ++i) < 0)
			i_unreached();
		value = mail_user_plugin_getenv(user, env_name);
	}
}

static void
autocreate_mail_namespaces_created(struct mail_namespace *namespaces)
{
	read_autobox_settings(namespaces->user, "autocreate", FALSE);
	read_autobox_settings(namespaces->user, "autosubscribe", TRUE);
}

static struct mail_storage_hooks autocreate_mail_storage_hooks = {
	.mail_namespaces_created = autocreate_mail_namespaces_created
};

void autocreate_plugin_init(struct module *module)
{
	i_warning("autocreate plugin is deprecated, use mailbox { auto } setting instead");
	mail_storage_hooks_add(module, &autocreate_mail_storage_hooks);
}

void autocreate_plugin_deinit(void)
{
	mail_storage_hooks_remove(&autocreate_mail_storage_hooks);
}
