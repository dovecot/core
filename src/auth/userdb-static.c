/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_STATIC

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

static pool_t static_pool;
static array_t ARRAY_DEFINE(static_template, const char *);

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
        const struct var_expand_table *table;
	struct auth_stream_reply *reply;
	string_t *str;
	const char *const *args;
	unsigned int i, count;

	t_push();
	str = t_str_new(256);
	table = auth_request_get_var_expand_table(auth_request, NULL);

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);

	args = array_get(&static_template, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		str_truncate(str, 0);
		var_expand(str, args[i+1], table);
		auth_stream_reply_add(reply, args[i], str_c(str));
	}

	callback(reply, auth_request);
	t_pop();
}

static void static_init(const char *args)
{
	const char *const *tmp, *key, *value;
	uid_t uid;
	gid_t gid;

	static_pool = pool_alloconly_create("static userdb", 256);
	uid = (uid_t)-1;
	gid = (gid_t)-1;

	ARRAY_CREATE(&static_template, static_pool, const char *, 16);

	t_push();
	for (tmp = t_strsplit_spaces(args, " "); *tmp != NULL; tmp++) {
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
		}
		key = p_strdup(static_pool, key);
		value = p_strdup(static_pool, value);

		array_append(&static_template, &key, 1);
		array_append(&static_template, &value, 1);
	}
	t_pop();

	if (uid == (uid_t)-1)
		i_fatal("static userdb: uid missing");
	if (gid == (gid_t)-1)
		i_fatal("static userdb: gid missing");
}

static void static_deinit(void)
{
	pool_unref(static_pool);
}

struct userdb_module userdb_static = {
	"static",
	FALSE,

	NULL,
	static_init,
	static_deinit,

	static_lookup
};

#endif
