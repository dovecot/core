/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hook-build.h"
#include "llist.h"
#include "module-dir.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"

struct mail_storage_module_hooks {
	struct module *module;
	const struct mail_storage_hooks *hooks;
	bool forced;
};

static ARRAY(struct mail_storage_module_hooks) module_hooks = ARRAY_INIT;
static ARRAY(const struct mail_storage_hooks *) internal_hooks = ARRAY_INIT;

void mail_storage_hooks_init(void)
{
	if (!array_is_created(&module_hooks))
		i_array_init(&module_hooks, 32);
	i_array_init(&internal_hooks, 8);
}

void mail_storage_hooks_deinit(void)
{
	/* allow calling this even if mail_storage_hooks_init() hasn't been
	   called, because e.g. doveadm plugins could call
	   mail_storage_hooks_add() even though mail storage is never
	   initialized. */
	if (array_is_created(&internal_hooks))
		array_free(&internal_hooks);
	if (array_is_created(&module_hooks))
		array_free(&module_hooks);
}

void mail_storage_hooks_add(struct module *module,
			    const struct mail_storage_hooks *hooks)
{
	struct mail_storage_module_hooks new_hook;

	i_zero(&new_hook);
	new_hook.module = module;
	new_hook.hooks = hooks;

	/* allow adding hooks before mail_storage_hooks_init() */
	if (!array_is_created(&module_hooks))
		i_array_init(&module_hooks, 32);
	array_push_back(&module_hooks, &new_hook);
}

void mail_storage_hooks_add_forced(struct module *module,
				   const struct mail_storage_hooks *hooks)
{
	struct mail_storage_module_hooks *hook;

	mail_storage_hooks_add(module, hooks);
	hook = array_idx_modifiable(&module_hooks,
				    array_count(&module_hooks)-1);
	hook->forced = TRUE;
}

void mail_storage_hooks_remove(const struct mail_storage_hooks *hooks)
{
	const struct mail_storage_module_hooks *module_hook;
	unsigned int idx = UINT_MAX;

	array_foreach(&module_hooks, module_hook) {
		if (module_hook->hooks == hooks) {
			idx = array_foreach_idx(&module_hooks, module_hook);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&module_hooks, idx, 1);
}

void mail_storage_hooks_add_internal(const struct mail_storage_hooks *hooks)
{
	const struct mail_storage_hooks *const *existing_hooksp;

	/* make sure we don't add duplicate hooks */
	array_foreach(&internal_hooks, existing_hooksp)
		i_assert(*existing_hooksp != hooks);
	array_push_back(&internal_hooks, &hooks);
}

void mail_storage_hooks_remove_internal(const struct mail_storage_hooks *hooks)
{
	const struct mail_storage_hooks *const *old_hooks;
	unsigned int idx = UINT_MAX;

	array_foreach(&internal_hooks, old_hooks) {
		if (*old_hooks == hooks) {
			idx = array_foreach_idx(&internal_hooks, old_hooks);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&internal_hooks, idx, 1);
}

static int
mail_storage_module_hooks_cmp(const struct mail_storage_module_hooks *h1,
			      const struct mail_storage_module_hooks *h2)
{
	const char *s1 = h1->module->path, *s2 = h2->module->path;
	const char *p;

	p = strrchr(s1, '/');
	if (p != NULL) s1 = p+1;
	p = strrchr(s2, '/');
	if (p != NULL) s2 = p+1;

	if (str_begins(s1, "lib"))
		s1 += 3;
	if (str_begins(s2, "lib"))
		s2 += 3;

	return strcmp(s1, s2);
}

static void mail_user_add_plugin_hooks(struct mail_user *user)
{
	const struct mail_storage_module_hooks *module_hook;
	ARRAY(struct mail_storage_module_hooks) tmp_hooks;
	const char *const *plugins, *name;

	/* first get all hooks wanted by the user */
	t_array_init(&tmp_hooks, array_count(&module_hooks));
	plugins = t_strsplit_spaces(user->set->mail_plugins, ", ");
	array_foreach(&module_hooks, module_hook) {
		if (!module_hook->forced) {
			name = module_get_plugin_name(module_hook->module);
			if (!str_array_find(plugins, name))
				continue;
		}
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
	struct hook_build_context *ctx;

	mail_user_add_plugin_hooks(user);

	ctx = hook_build_init((void *)&user->v, sizeof(user->v));
	user->vlast = &user->v;
	array_foreach(&user->hooks, hooks) {
		if ((*hooks)->mail_user_created != NULL) T_BEGIN {
			(*hooks)->mail_user_created(user);
			hook_build_update(ctx, user->vlast);
		} T_END;
	}
	user->vlast = NULL;
	hook_build_deinit(&ctx);
}

void hook_mail_namespace_storage_added(struct mail_namespace *ns)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&ns->user->hooks, hooks) {
		if ((*hooks)->mail_namespace_storage_added != NULL) T_BEGIN {
			(*hooks)->mail_namespace_storage_added(ns);
		} T_END;
	}
}

void hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&namespaces->user->hooks, hooks) {
		if (namespaces->user->error != NULL)
			break;
		if ((*hooks)->mail_namespaces_created != NULL) T_BEGIN {
			(*hooks)->mail_namespaces_created(namespaces);
		} T_END;
	}
}

void hook_mail_namespaces_added(struct mail_namespace *namespaces)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&namespaces->user->hooks, hooks) {
		if (namespaces->user->error != NULL)
			break;
		if ((*hooks)->mail_namespaces_added != NULL) T_BEGIN {
			(*hooks)->mail_namespaces_added(namespaces);
		} T_END;
	}
}

void hook_mail_storage_created(struct mail_storage *storage)
{
	const struct mail_storage_hooks *const *hooks;
	struct hook_build_context *ctx;

	ctx = hook_build_init((void *)&storage->v, sizeof(storage->v));
	storage->vlast = &storage->v;
	array_foreach(&storage->user->hooks, hooks) {
		if ((*hooks)->mail_storage_created != NULL) T_BEGIN {
			(*hooks)->mail_storage_created(storage);
			hook_build_update(ctx, storage->vlast);
		} T_END;
	}
	storage->vlast = NULL;
	hook_build_deinit(&ctx);
}

void hook_mailbox_list_created(struct mailbox_list *list)
{
	const struct mail_storage_hooks *const *hooks;
	struct hook_build_context *ctx;

	ctx = hook_build_init((void *)&list->v, sizeof(list->v));
	list->vlast = &list->v;
	array_foreach(&list->ns->user->hooks, hooks) {
		if ((*hooks)->mailbox_list_created != NULL) T_BEGIN {
			(*hooks)->mailbox_list_created(list);
			hook_build_update(ctx, list->vlast);
		} T_END;
	}
	list->vlast = NULL;
	hook_build_deinit(&ctx);
}

void hook_mailbox_allocated(struct mailbox *box)
{
	const struct mail_storage_hooks *const *hooks;
	struct hook_build_context *ctx;

	ctx = hook_build_init((void *)&box->v, sizeof(box->v));
	box->vlast = &box->v;
	array_foreach(&box->storage->user->hooks, hooks) {
		if ((*hooks)->mailbox_allocated != NULL) T_BEGIN {
			(*hooks)->mailbox_allocated(box);
			hook_build_update(ctx, box->vlast);
		} T_END;
	}
	box->vlast = NULL;
	hook_build_deinit(&ctx);
}

void hook_mailbox_opened(struct mailbox *box)
{
	const struct mail_storage_hooks *const *hooks;

	array_foreach(&box->storage->user->hooks, hooks) {
		if ((*hooks)->mailbox_opened != NULL) T_BEGIN {
			(*hooks)->mailbox_opened(box);
		} T_END;
	}
}

void hook_mail_allocated(struct mail *mail)
{
	const struct mail_storage_hooks *const *hooks;
	struct mail_private *pmail = (struct mail_private *)mail;
	struct hook_build_context *ctx;

	ctx = hook_build_init((void *)&pmail->v, sizeof(pmail->v));
	pmail->vlast = &pmail->v;
	array_foreach(&mail->box->storage->user->hooks, hooks) {
		if ((*hooks)->mail_allocated != NULL) T_BEGIN {
			(*hooks)->mail_allocated(mail);
			hook_build_update(ctx, pmail->vlast);
		} T_END;
	}
	pmail->vlast = NULL;
	hook_build_deinit(&ctx);
}
