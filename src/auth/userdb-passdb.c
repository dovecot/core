/* Copyright (C) 2004 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSDB

#include "common.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

static void passdb_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback, void *context)
{
	struct user_data data;
	const char *const *args;
	int uid_seen, gid_seen;

	memset(&data, 0, sizeof(data));
	data.virtual_user = auth_request->user;

	uid_seen = gid_seen = FALSE;
	data.uid = (uid_t)-1;
	data.gid = (gid_t)-1;

	t_push();
	args = t_strsplit(auth_request->extra_fields, "\t");
	for (; *args != NULL; args++) {
		const char *arg = *args;

		if (strncmp(arg, "userdb_", 7) != 0)
			continue;
		arg += 7;

		if (strncmp(arg, "uid=", 4) == 0) {
			uid_seen = TRUE;
                        data.uid = userdb_parse_uid(auth_request, arg+4);
		} else if (strncmp(arg, "gid=", 4) == 0) {
			gid_seen = TRUE;
			data.gid = userdb_parse_gid(auth_request, arg+4);
		} else if (strncmp(arg, "home=", 5) == 0)
			data.home = arg + 5;
		else if (strncmp(arg, "mail=", 5) == 0)
			data.mail = arg + 5;
	}

	if (!uid_seen) {
		i_error("passdb(%s): userdb_uid not returned",
			get_log_prefix(auth_request));
	}
	if (!gid_seen) {
		i_error("passdb(%s): userdb_gid not returned",
			get_log_prefix(auth_request));
	}

	if (data.uid == (uid_t)-1 || data.gid == (gid_t)-1)
		callback(NULL, context);
	else
		callback(&data, context);
	t_pop();
}

struct userdb_module userdb_passdb = {
	"passdb",

	NULL,
	NULL,
	NULL,

	passdb_lookup
};

#endif
