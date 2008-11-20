/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-user.h"

struct mail_user_module_register mail_user_module_register = { 0 };
void (*hook_mail_user_created)(struct mail_user *user) = NULL;

static void mail_user_deinit_base(struct mail_user *user)
{
	mail_namespaces_deinit(&user->namespaces);
	pool_unref(&user->pool);
}

struct mail_user *mail_user_init(const char *username, const char *home)
{
	struct mail_user *user;
	pool_t pool;

	i_assert(username != NULL);

	pool = pool_alloconly_create("mail user", 512);
	user = p_new(pool, struct mail_user, 1);
	user->pool = pool;
	user->username = p_strdup_empty(pool, username);
	user->home = p_strdup(pool, home);
	user->v.deinit = mail_user_deinit_base;
	p_array_init(&user->module_contexts, user->pool, 5);

	if (hook_mail_user_created != NULL)
		hook_mail_user_created(user);
	return user;
}

void mail_user_deinit(struct mail_user **_user)
{
	struct mail_user *user = *_user;

	*_user = NULL;
	user->v.deinit(user);
}

void mail_user_add_namespace(struct mail_user *user, struct mail_namespace *ns)
{
	struct mail_namespace **tmp, *next;

	for (; ns != NULL; ns = next) {
		next = ns->next;

		tmp = &user->namespaces;
		for (; *tmp != NULL; tmp = &(*tmp)->next) {
			if (strlen(ns->prefix) < strlen((*tmp)->prefix))
				break;
		}
		ns->next = *tmp;
		*tmp = ns;
	}
}

void mail_user_drop_useless_namespaces(struct mail_user *user)
{
	struct mail_namespace *ns, *next;

	for (ns = user->namespaces; ns != NULL; ns = next) {
		next = ns->next;

		if ((ns->flags & NAMESPACE_FLAG_USABLE) == 0 &&
		    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0)
			mail_namespace_destroy(ns);
	}
}

const char *mail_user_home_expand(struct mail_user *user, const char *path)
{
	(void)mail_user_try_home_expand(user, &path);
	return path;
}

int mail_user_try_home_expand(struct mail_user *user, const char **pathp)
{
	const char *path = *pathp;

	if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
		if (user->home == NULL)
			return -1;

		*pathp = t_strconcat(user->home, path + 1, NULL);
	}
	return 0;
}
