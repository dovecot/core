/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_STATIC

#include "common.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

static uid_t static_uid;
static gid_t static_gid;
static char *static_home_template;

static void static_lookup(const char *user, const char *realm,
			  userdb_callback_t *callback, void *context)
{
	struct user_data *data;
	pool_t pool;
	string_t *str;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);

	pool = pool_alloconly_create("user_data", 512);
	data = p_new(pool, struct user_data, 1);
	data->pool = pool;

	data->uid = static_uid;
	data->gid = static_gid;

	data->system_user = p_strdup(data->pool, user);
	data->virtual_user = data->system_user;

	str = t_str_new(256);
	var_expand(str, static_home_template, user, NULL);
	data->home = p_strdup(data->pool, str_c(str));

	callback(data, context);
}

static void static_init(const char *args)
{
	const char *const *tmp;

	static_uid = 0;
	static_gid = 0;
	static_home_template = NULL;

	for (tmp = t_strsplit(args, " "); *tmp != NULL; tmp++) {
		if (**tmp == '\0')
			continue;

		if (strncasecmp(*tmp, "uid=", 4) == 0)
			static_uid = atoi(*tmp + 4);
		else if (strncasecmp(*tmp, "gid=", 4) == 0)
			static_gid = atoi(*tmp + 4);
		else if (strncasecmp(*tmp, "home=", 5) == 0) {
			i_free(static_home_template);
			static_home_template = i_strdup(*tmp + 5);
		} else {
			i_fatal("Invalid static userdb option: '%s'", *tmp);
		}
	}

	if (static_uid == 0)
		i_fatal("static userdb: uid missing");
	if (static_gid == 0)
		i_fatal("static userdb: gid missing");
	if (static_home_template == NULL)
		i_fatal("static userdb: home option missing");
}

static void static_deinit(void)
{
	i_free(static_home_template);
}

struct userdb_module userdb_static = {
	static_init,
	static_deinit,

	static_lookup
};

#endif
