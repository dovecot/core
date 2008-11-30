/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "auth-master.h"
#include "mail-namespace.h"
#include "mail-user.h"

#include <stdlib.h>

struct mail_user_module_register mail_user_module_register = { 0 };
void (*hook_mail_user_created)(struct mail_user *user) = NULL;

static struct auth_master_connection *auth_master_conn;

static void mail_user_deinit_base(struct mail_user *user)
{
	mail_namespaces_deinit(&user->namespaces);
	pool_unref(&user->pool);
}

struct mail_user *mail_user_init(const char *username)
{
	struct mail_user *user;
	pool_t pool;

	i_assert(username != NULL);

	pool = pool_alloconly_create("mail user", 512);
	user = p_new(pool, struct mail_user, 1);
	user->pool = pool;
	user->refcount = 1;
	user->username = p_strdup_empty(pool, username);
	user->v.deinit = mail_user_deinit_base;
	p_array_init(&user->module_contexts, user->pool, 5);

	if (hook_mail_user_created != NULL)
		hook_mail_user_created(user);
	return user;
}

void mail_user_ref(struct mail_user *user)
{
	i_assert(user->refcount > 0);

	user->refcount++;
}

void mail_user_unref(struct mail_user **_user)
{
	struct mail_user *user = *_user;

	i_assert(user->refcount > 0);

	*_user = NULL;
	if (--user->refcount == 0)
		user->v.deinit(user);
}

struct mail_user *mail_user_find(struct mail_user *user, const char *name)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->owner != NULL && strcmp(ns->owner->username, name) == 0)
			return ns->owner;
	}
	return NULL;
}

void mail_user_set_home(struct mail_user *user, const char *home)
{
	user->_home = p_strdup(user->pool, home);
	user->home_looked_up = TRUE;
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

int mail_user_get_home(struct mail_user *user, const char **home_r)
{
	struct auth_user_reply reply;
	pool_t userdb_pool;
	int ret;

	if (user->home_looked_up) {
		*home_r = user->_home;
		return user->_home != NULL ? 1 : 0;
	}

	userdb_pool = pool_alloconly_create("userdb lookup", 512);
	ret = auth_master_user_lookup(auth_master_conn, user->username,
				      AUTH_SERVICE_INTERNAL,
				      userdb_pool, &reply);
	if (ret < 0)
		*home_r = NULL;
	else {
		user->_home = ret == 0 ? NULL :
			p_strdup(user->pool, reply.home);
		user->home_looked_up = TRUE;
		ret = user->_home != NULL ? 1 : 0;
		*home_r = user->_home;
	}
	pool_unref(&userdb_pool);
	return ret;
}

int mail_user_try_home_expand(struct mail_user *user, const char **pathp)
{
	const char *home, *path = *pathp;

	if (mail_user_get_home(user, &home) < 0)
		return -1;

	if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
		if (home == NULL)
			return -1;

		*pathp = t_strconcat(home, path + 1, NULL);
	}
	return 0;
}

void mail_users_init(const char *auth_socket_path, bool debug)
{
	const char *base_dir;

	if (auth_socket_path == NULL) {
		base_dir = getenv("BASE_DIR");
		if (base_dir == NULL)
			base_dir = PKG_RUNDIR;
		auth_socket_path = t_strconcat(base_dir, "/auth-master", NULL);
	}
	auth_master_conn = auth_master_init(auth_socket_path, debug);
}

void mail_users_deinit(void)
{
	auth_master_deinit(&auth_master_conn);
}
