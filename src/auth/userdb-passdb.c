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
	const char *const *args;
	string_t *str;
	uid_t uid;
	gid_t gid;
	int uid_seen, gid_seen;

	if (auth_request->extra_fields == NULL) {
		auth_request_log_error(auth_request, "passdb",
				       "passdb didn't return userdb entries");
		callback(NULL, context);
		return;
	}

	t_push();

	uid = (uid_t)-1; gid = (gid_t)-1;
	uid_seen = gid_seen = FALSE;

	str = t_str_new(256);
	str_append(str, auth_request->user);

	args = t_strsplit(auth_request->extra_fields, "\t");
	for (; *args != NULL; args++) {
		const char *arg = *args;

		if (strncmp(arg, "userdb_", 7) != 0)
			continue;
		arg += 7;

		str_append_c(str, '\t');
		if (strncmp(arg, "uid=", 4) == 0) {
			uid_seen = TRUE;
			uid = userdb_parse_uid(auth_request, arg+4);
			if (uid == (uid_t)-1)
				break;

			str_append(str, "uid=");
			str_append(str, dec2str(uid));
		} else if (strncmp(arg, "gid=", 4) == 0) {
			gid_seen = TRUE;
			gid = userdb_parse_gid(auth_request, arg+4);
			if (gid == (gid_t)-1)
				break;

			str_append(str, "gid=");
			str_append(str, dec2str(gid));
		} else {
			str_append(str, arg);
		}
	}

	if (!uid_seen) {
		auth_request_log_error(auth_request, "passdb",
				       "userdb_uid not returned");
	}
	if (!gid_seen) {
		auth_request_log_error(auth_request, "passdb",
				       "userdb_gid not returned");
	}

	if (uid == (uid_t)-1 || gid == (gid_t)-1)
		callback(NULL, context);
	else
		callback(str_c(str), context);
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
