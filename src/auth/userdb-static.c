/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_STATIC

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

struct static_userdb_module {
	struct userdb_module module;

	array_t ARRAY_DEFINE(template, const char *);
};

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct static_userdb_module *module =
		(struct static_userdb_module *)_module;
        const struct var_expand_table *table;
	struct auth_stream_reply *reply;
	string_t *str;
	const char *const *args, *value;
	unsigned int i, count;

	t_push();
	str = t_str_new(256);
	table = auth_request_get_var_expand_table(auth_request, NULL);

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);

	args = array_get(&module->template, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (args[i+1] == NULL)
			value = NULL;
		else {
			str_truncate(str, 0);
			var_expand(str, args[i+1], table);
			value = str_c(str);
		}
		auth_stream_reply_add(reply, args[i], value);
	}

	callback(reply, auth_request);
	t_pop();
}

static struct userdb_module *
static_preinit(struct auth_userdb *auth_userdb, const char *args)
{
	struct static_userdb_module *module;
	const char *const *tmp, *key, *value;
	uid_t uid;
	gid_t gid;

	module = p_new(auth_userdb->auth->pool, struct static_userdb_module, 1);

	uid = (uid_t)-1;
	gid = (gid_t)-1;

	tmp = t_strsplit_spaces(args, " ");
	ARRAY_CREATE(&module->template, auth_userdb->auth->pool,
		     const char *, strarray_length(tmp));

	t_push();
	for (; *tmp != NULL; tmp++) {
		value = strchr(*tmp, '=');
		if (value == NULL)
			key = *tmp;
		else {
			key = t_strdup_until(*tmp, value);
			value++;
		}

		if (strcasecmp(key, "uid") == 0) {
			uid = userdb_parse_uid(NULL, value);
			if (uid == (uid_t)-1) {
				i_fatal("static userdb: Invalid uid: %s",
					value);
			}
			value = dec2str(uid);
		} else if (strcasecmp(key, "gid") == 0) {
			gid = userdb_parse_gid(NULL, value);
			if (gid == (gid_t)-1) {
				i_fatal("static userdb: Invalid gid: %s",
					value);
			}
			value = dec2str(gid);
		} else if (*key == '\0') {
			i_fatal("Status userdb: Empty key (=%s)", value);
		}
		key = p_strdup(auth_userdb->auth->pool, key);
		value = p_strdup(auth_userdb->auth->pool, value);

		array_append(&module->template, &key, 1);
		array_append(&module->template, &value, 1);
	}
	t_pop();

	if (uid == (uid_t)-1)
		i_fatal("static userdb: uid missing");
	if (gid == (gid_t)-1)
		i_fatal("static userdb: gid missing");
	return &module->module;
}

struct userdb_module_interface userdb_static = {
	"static",

	static_preinit,
	NULL,
	NULL,

	static_lookup
};

#endif
