/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD

#include "common.h"
#include "userdb.h"

#include <pwd.h>

static struct user_data *passwd_lookup(const char *user, const char *realm)
{
	struct user_data *data;
	struct passwd *pw;
	pool_t pool;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);
	pw = getpwnam(user);
	if (pw == NULL) {
		if (errno != 0)
			i_error("getpwnam(%s) failed: %m", user);
		else if (verbose)
			i_info("passwd(%s): unknown user", user);
		return NULL;
	}

	pool = pool_alloconly_create("user_data", 512);
	data = p_new(pool, struct user_data, 1);
	data->pool = pool;

	data->uid = pw->pw_uid;
	data->gid = pw->pw_gid;

	data->system_user = p_strdup(data->pool, pw->pw_name);
	data->virtual_user = data->system_user;
	data->home = p_strdup(data->pool, pw->pw_dir);

	return data;
}

struct userdb_module userdb_passwd = {
	NULL, NULL,
	passwd_lookup
};

#endif
