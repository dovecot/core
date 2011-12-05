/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

/* FIXME: this plugin is only for backwards compatibility. log a warning in
   v2.2 about this and in later versions remove completely */

#include "lib.h"
#include "array.h"
#include "unichar.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "autocreate-plugin.h"

static struct mailbox_settings *
mailbox_settings_find(struct mail_user *user, const char *vname)
{
	struct mailbox_settings *const *box_set;

	array_foreach(&user->set->mailboxes, box_set) {
		if (strcmp((*box_set)->name, vname) == 0)
			return *box_set;
	}
	return NULL;
}

static void
add_autobox(struct mail_user *user, const char *vname, bool subscriptions)
{
	struct mailbox_settings *set;

	if (!uni_utf8_str_is_valid(vname)) {
		i_error("autocreate: Mailbox name isn't valid UTF-8: %s",
			vname);
		return;
	}

	set = mailbox_settings_find(user, vname);
	if (set == NULL) {
		set = p_new(user->pool, struct mailbox_settings, 1);
		set->name = p_strdup(user->pool, vname);
		set->autocreate = MAILBOX_SET_AUTO_NO;
		array_append(&user->set->mailboxes, &set, 1);
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
	char env_name[20];
	unsigned int i = 1;

	value = mail_user_plugin_getenv(user, env_name_base);
	while (value != NULL) {
		add_autobox(user, value, subscriptions);

		i_snprintf(env_name, sizeof(env_name), "%s%d",
			   env_name_base, ++i);
		value = mail_user_plugin_getenv(user, env_name);
	}
}

static void
autocreate_mail_user_created(struct mail_user *user)
{
	if (!array_is_created(&user->set->mailboxes))
		p_array_init(&user->set->mailboxes, user->pool, 16);

	read_autobox_settings(user, "autocreate", FALSE);
	read_autobox_settings(user, "autosubscribe", TRUE);
}

static struct mail_storage_hooks autocreate_mail_storage_hooks = {
	.mail_user_created = autocreate_mail_user_created
};

void autocreate_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &autocreate_mail_storage_hooks);
}

void autocreate_plugin_deinit(void)
{
	mail_storage_hooks_remove(&autocreate_mail_storage_hooks);
}
