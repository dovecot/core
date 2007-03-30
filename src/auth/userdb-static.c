/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_STATIC

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"

#include <stdlib.h>

struct static_context {
	userdb_callback_t *callback, *old_callback;
	void *old_context;
};

struct static_userdb_module {
	struct userdb_module module;

	ARRAY_DEFINE(template, const char *);

	unsigned int allow_all_users:1;
};

static void static_lookup_real(struct auth_request *auth_request,
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

	callback(USERDB_RESULT_OK, reply, auth_request);
	t_pop();
}

static bool
static_credentials_callback(enum passdb_result result,
			    const char *password __attr_unused__,
			    struct auth_request *auth_request)
{
	struct static_context *ctx = auth_request->context;

	auth_request->private_callback.userdb = ctx->old_callback;
	auth_request->context = ctx->old_context;
	auth_request->state = AUTH_REQUEST_STATE_USERDB;

	switch (result) {
	case PASSDB_RESULT_OK:
		static_lookup_real(auth_request, ctx->callback);
		break;
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		ctx->callback(USERDB_RESULT_USER_UNKNOWN, NULL, auth_request);
		break;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		auth_request_log_error(auth_request, "static",
			"passdb doesn't support lookups, "
			"can't verify user's existence");
		/* fall through */
	default:
		ctx->callback(USERDB_RESULT_INTERNAL_FAILURE,
			      NULL, auth_request);
		break;
	}

	i_free(ctx);
	return TRUE;
}

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct static_userdb_module *module =
		(struct static_userdb_module *)_module;
	struct static_context *ctx;

	if (!auth_request->successful && !module->allow_all_users) {
		/* this is a userdb-only lookup. we need to know if this
		   users exists or not. use a passdb lookup to do that.
		   if the passdb doesn't support returning credentials, this
		   will of course fail.. */
		ctx = i_new(struct static_context, 1);
		ctx->old_callback = auth_request->private_callback.userdb;
		ctx->old_context = auth_request->context;
		ctx->callback = callback;

		i_assert(auth_request->state == AUTH_REQUEST_STATE_USERDB);
		auth_request->state = AUTH_REQUEST_STATE_MECH_CONTINUE;

		auth_request->context = ctx;
		auth_request_lookup_credentials(auth_request,
						PASSDB_CREDENTIALS_CRYPT,
						static_credentials_callback);
	} else {
		static_lookup_real(auth_request, callback);
	}
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
	p_array_init(&module->template, auth_userdb->auth->pool,
		     strarray_length(tmp));

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
		} else if (strcmp(key, "allow_all_users") == 0) {
			module->allow_all_users = value == NULL ||
				strcasecmp(value, "yes") == 0;
			continue;
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
