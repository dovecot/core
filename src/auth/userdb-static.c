/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_STATIC

#include "common.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

static char *static_template;

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback, void *context)
{
	string_t *str;

	str = t_str_new(128);
	str_append(str, auth_request->user);
	var_expand(str, static_template,
		   auth_request_get_var_expand_table(auth_request, NULL));
	callback(str_c(str), context);
}

static void static_init(const char *args)
{
	const char *const *tmp;
	uid_t uid;
	gid_t gid;
	string_t *str;

	uid = (uid_t)-1;
	gid = (gid_t)-1;

	t_push();
	str = t_str_new(128);

	for (tmp = t_strsplit_spaces(args, " "); *tmp != NULL; tmp++) {
		str_append_c(str, '\t');
		if (strncasecmp(*tmp, "uid=", 4) == 0) {
			uid = userdb_parse_uid(NULL, *tmp + 4);
			if (uid == (uid_t)-1) {
				i_fatal("static userdb: Invalid uid: %s",
					*tmp + 4);
			}
			str_append(str, "uid=");
			str_append(str, dec2str(uid));
		} else if (strncasecmp(*tmp, "gid=", 4) == 0) {
			gid = userdb_parse_gid(NULL, *tmp + 4);
			if (gid == (gid_t)-1) {
				i_fatal("static userdb: Invalid gid: %s",
					*tmp + 4);
			}
			str_append(str, "gid=");
			str_append(str, dec2str(gid));
		} else {
			str_append(str, *tmp);
		}
	}

	if (uid == (uid_t)-1)
		i_fatal("static userdb: uid missing");
	if (gid == (gid_t)-1)
		i_fatal("static userdb: gid missing");

	static_template = i_strdup(str_c(str));
	t_pop();
}

static void static_deinit(void)
{
	i_free(static_template);
}

struct userdb_module userdb_static = {
	"static",

	NULL,
	static_init,
	static_deinit,

	static_lookup
};

#endif
