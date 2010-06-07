/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "module-dir.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"

struct mail_storage_module_hooks {
	struct module *module;
	const struct mail_storage_hooks *hooks;
};

static ARRAY_DEFINE(module_hooks,
		    struct mail_storage_module_hooks) = ARRAY_INIT;
static ARRAY_DEFINE(internal_hooks,
		    const struct mail_storage_hooks *) = ARRAY_INIT;

void mail_storage_hooks_init(void)
{
	i_array_init(&module_hooks, 32);
	i_array_init(&internal_hooks, 8);
}

void mail_storage_hooks_deinit(void)
{
	array_free(&internal_hooks);
	array_free(&module_hooks);
}

void mail_storage_hooks_add(struct module *module,
			    const struct mail_storage_hooks *hooks)
{
	struct mail_storage_module_hooks new_hook;

	memset(&new_hook, 0, sizeof(new_hook));
	new_hook.module = module;
	new_hook.hooks = hooks;

	array_append(&module_hooks, &new_hook, 1);
}

void mail_storage_hooks_remove(const struct mail_storage_hooks *hooks)
{
	const struct mail_storage_module_hooks *module_hook;
	unsigned int idx = -1U;

	array_foreach(&module_hooks, module_hook) {
		if (module_hook->hooks == hooks) {
			idx = array_foreach_idx(&module_hooks, module_hook);
			break;
		}
	}
	i_assert(idx != -1U);

	array_delete(&module_hooks, idx, 1);
}

void mail_storage_hooks_add_internal(const struct mail_storage_hooks *hooks)
{
	array_append(&internal_hooks, &hooks, 1);
}

void mail_storage_hooks_remove_internal(const struct mail_storage_hooks *hooks)
{
	const struct mail_storage_hooks *const *old_hooks;
	unsigned int idx = -1U;

	array_foreach(&internal_hooks, old_hooks) {
		if (*old_hooks == hooks) {
			idx = array_foreach_idx(&internal_hooks, old_hooks);
			break;
		}
	}
	i_assert(idx != -1U);

	array_delete(&internal_hooks, idx, 1);
}

static int
mail_storage_module_hooks_cmp(const struct mail_storage_module_hooks *h1,
			      const struct mail_storage_module_hooks *h2)
{
	const char *s1 = h1->module->path, *s2 = h2->module->path;

	if (strncmp(s1, "lib", 3) == 0)
		s1 += 3;
	if (strncmp(s2, "lib", 3) == 0)
		s2 += 3;

	return strcmp(s1, s2);
}

static void mail_user_add_plugin_hooks(struct mail_user *user)
{
	const struct mail_storage_module_hooks *module_hook;
	ARRAY_DEFINE(tmp_hooks, struct mail_storage_module_hooks);
	const char *const *plugins, *name;

	/* first get all hooks wanted by the user */
	t_array_init(&tmp_hooks, array_count(&module_hooks));
	plugins = t_strsplit_spaces(user->set->mail_plugins, ", ");
	array_foreach(&module_hooks, module_hook) {
		name = module_get_plugin_name(module_hook->module);
		if (str_array_find(plugins, name))
			array_append(&tmp_hooks, module_hook, 1);
	}

	/* next we have to sort them by the modules' priority (based on name) */
	array_sort(&tmp_hooks, mail_storage_module_hooks_cmp);

	/* now that we have them in order, save them to user's hooks */
	p_array_init(&user->hooks, user->pool,
		     array_count(&tmp_hooks) + array_count(&internal_hooks));
	array_foreach(&tmp_hooks, module_hook)
		array_append(&user->hooks, &module_hook->hooks, 1);
	array_append_array(&user->hooks, &internal_hooks);
}

void hook_mail_user_created(struct mail_user *user)
{
	const struct mail_storage_hooks *const *hooks;

	mail_user_add_plugin_hooks(user);

	user->vlast = &user->v;
	array_foreach(&user->hooks, hooks) {
		if ((*hooks)->mail_user_created != NULL)
			(*hooks)->mail_user_created(user);
	}
}

void hook_mail_namespace_storage_added(struct mail_namespace *ns)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&ns->user->hooks, hooks) {
		if ((*hooks)->mail_namespace_storage_added != NULL)
			(*hooks)->mail_namespace_storage_added(ns);
	}
}

void hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&namespaces->user->hooks, hooks) {
		if ((*hooks)->mail_namespaces_created != NULL)
			(*hooks)->mail_namespaces_created(namespaces);
	}
}

void hook_mail_storage_created(struct mail_storage *storage)
{
	const struct mail_storage_hooks *const *hooks;

	storage->vlast = &storage->v;
	array_foreach(&storage->user->hooks, hooks) {
		if ((*hooks)->mail_storage_created != NULL)
			(*hooks)->mail_storage_created(storage);
	}
}

void hook_mailbox_list_created(struct mailbox_list *list)
{
	const struct mail_storage_hooks *const *hooks;

	list->vlast = &list->v;
	array_foreach(&list->ns->user->hooks, hooks) {
		if ((*hooks)->mailbox_list_created != NULL)
			(*hooks)->mailbox_list_created(list);
	}
}

void hook_mailbox_allocated(struct mailbox *box)
{
	const struct mail_storage_hooks *const *hooks;

	box->vlast = &box->v;
	array_foreach(&box->storage->user->hooks, hooks) {
		if ((*hooks)->mailbox_allocated != NULL)
			(*hooks)->mailbox_allocated(box);
	}
}

void hook_mailbox_opened(struct mailbox *box)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&box->storage->user->hooks, hooks) {
		if ((*hooks)->mailbox_opened != NULL)
			(*hooks)->mailbox_opened(box);
	}
}

void hook_mail_allocated(struct mail *mail)
{
	const struct mail_storage_hooks *const *hooks;
	struct mail_private *pmail = (struct mail_private *)mail;

	pmail->vlast = &pmail->v;
	array_foreach(&mail->box->storage->user->hooks, hooks) {
		if ((*hooks)->mail_allocated != NULL)
			(*hooks)->mail_allocated(mail);
	}
}
