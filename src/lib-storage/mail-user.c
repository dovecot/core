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
	user->username = p_strdup(pool, username);
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
