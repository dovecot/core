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
static char *static_home_template, *static_mail_template;

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback, void *context)
{
	struct user_data data;
	string_t *str;

	memset(&data, 0, sizeof(data));
	data.uid = static_uid;
	data.gid = static_gid;

	data.virtual_user = data.system_user = auth_request->user;

	if (static_home_template != NULL) {
		str = t_str_new(256);
		var_expand(str, static_home_template,
			   auth_request_get_var_expand_table(auth_request,
							     NULL));
		data.home = str_c(str);
	}
	if (static_mail_template != NULL) {
		str = t_str_new(256);
		var_expand(str, static_mail_template,
			   auth_request_get_var_expand_table(auth_request,
							     NULL));
		data.mail = str_c(str);
	}

	callback(&data, context);
}

static void static_init(const char *args)
{
	const char *const *tmp;

	static_uid = 0;
	static_gid = 0;
	static_home_template = NULL;
	static_mail_template = NULL;

	for (tmp = t_strsplit_spaces(args, " "); *tmp != NULL; tmp++) {
		if (strncasecmp(*tmp, "uid=", 4) == 0)
			static_uid = atoi(*tmp + 4);
		else if (strncasecmp(*tmp, "gid=", 4) == 0)
			static_gid = atoi(*tmp + 4);
		else if (strncasecmp(*tmp, "home=", 5) == 0) {
			i_free(static_home_template);
			static_home_template = i_strdup(*tmp + 5);
		} else if (strncasecmp(*tmp, "mail=", 5) == 0) {
			i_free(static_mail_template);
			static_mail_template = i_strdup(*tmp + 5);
		} else {
			i_fatal("Invalid static userdb option: '%s'", *tmp);
		}
	}

	if (static_uid == 0)
		i_fatal("static userdb: uid missing");
	if (static_gid == 0)
		i_fatal("static userdb: gid missing");
}

static void static_deinit(void)
{
	i_free(static_home_template);
	i_free(static_mail_template);
}

struct userdb_module userdb_static = {
	NULL,
	static_init,
	static_deinit,

	static_lookup
};

#endif
