/* Copyright (C) 2004 Timo Sirainen */

#include "common.h"

#ifdef USERDB_PREFETCH

#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

static void prefetch_lookup(struct auth_request *auth_request,
			    userdb_callback_t *callback)
{
	const char *const *args;
	string_t *str;
	uid_t uid;
	gid_t gid;
	bool uid_seen, gid_seen;

	if (auth_stream_is_empty(auth_request->extra_fields)) {
		if (auth_request->auth->userdbs->next == NULL) {
			/* no other userdbs */
			auth_request_log_error(auth_request, "prefetch",
				"passdb didn't return userdb entries");
		} else {
			/* more userdbs, they may know the user */
			auth_request_log_info(auth_request, "prefetch",
				"passdb didn't return userdb entries");
		}
		callback(USERDB_RESULT_USER_UNKNOWN, NULL, auth_request);
		return;
	}

	t_push();

	uid = (uid_t)-1; gid = (gid_t)-1;
	uid_seen = gid_seen = FALSE;

	str = t_str_new(256);
	str_append(str, auth_request->user);

	/* export the request. keep all keys starting with userdb_ but strip
	   the userdb_ away. */
	args = t_strsplit(auth_stream_reply_export(auth_request->extra_fields),
		"\t");
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
		auth_request_log_error(auth_request, "prefetch",
				       "userdb_uid not returned");
	}
	if (!gid_seen) {
		auth_request_log_error(auth_request, "prefetch",
				       "userdb_gid not returned");
	}

	if (uid == (uid_t)-1 || gid == (gid_t)-1)
		callback(USERDB_RESULT_USER_UNKNOWN, NULL, auth_request);
	else {
		struct auth_stream_reply *reply;

		auth_request_log_debug(auth_request, "prefetch", "success");

		/* import the string into request. since the values were
		   exported they are already in escaped form in the string. */
		reply = auth_stream_reply_init(auth_request);
		auth_stream_reply_import(reply, str_c(str));
		callback(USERDB_RESULT_OK, reply, auth_request);
	}
	t_pop();
}

struct userdb_module_interface userdb_prefetch = {
	"prefetch",

	NULL,
	NULL,
	NULL,

	prefetch_lookup
};

#endif
