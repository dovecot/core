/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD_FILE

#include "common.h"
#include "userdb.h"
#include "passwd-file.h"

struct passwd_file *userdb_pwf = NULL;

static struct user_data *passwd_file_lookup(const char *user, const char *realm)
{
	struct user_data *data;
	struct passwd_user *pu;
	pool_t pool;

	pu = passwd_file_lookup_user(userdb_pwf, user, realm);
	if (pu == NULL)
		return NULL;

	pool = pool_alloconly_create("user_data", 512);
	data = p_new(pool, struct user_data, 1);
	data->pool = pool;

	data->uid = pu->uid;
	data->gid = pu->gid;

	data->virtual_user = realm == NULL ? p_strdup(data->pool, user) :
		p_strconcat(data->pool, user, "@", realm, NULL);
	data->home = p_strdup(data->pool, pu->home);
	data->mail = p_strdup(data->pool, pu->mail);

	data->chroot = pu->chroot;
	return data;
}

static void passwd_file_init(const char *args)
{
	if (passdb_pwf != NULL && strcmp(passdb_pwf->path, args) == 0) {
		userdb_pwf = passdb_pwf;
                userdb_pwf->refcount++;
	} else {
		userdb_pwf = passwd_file_parse(args);
	}
}

static void passwd_file_deinit(void)
{
	passwd_file_unref(userdb_pwf);
}

struct userdb_module userdb_passwd_file = {
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_lookup
};

#endif
