/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"
#include "userdb-static.h"

#include <stdlib.h>

struct userdb_static_template {
	ARRAY_DEFINE(args, const char *);
};

struct userdb_static_template *
userdb_static_template_build(pool_t pool, const char *userdb_name,
			     const char *args)
{
	struct userdb_static_template *tmpl;
	const char *const *tmp, *key, *value;
	uid_t uid;
	gid_t gid;

	tmpl = p_new(pool, struct userdb_static_template, 1);

	tmp = t_strsplit_spaces(args, " ");
	p_array_init(&tmpl->args, pool, str_array_length(tmp));

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
				i_fatal("%s userdb: Invalid uid: %s",
					userdb_name, value);
			}
			value = dec2str(uid);
		} else if (strcasecmp(key, "gid") == 0) {
			gid = userdb_parse_gid(NULL, value);
			if (gid == (gid_t)-1) {
				i_fatal("%s userdb: Invalid gid: %s",
					userdb_name, value);
			}
			value = dec2str(gid);
		} else if (*key == '\0') {
			i_fatal("%s userdb: Empty key (=%s)",
				userdb_name, value);
		}
		key = p_strdup(pool, key);
		value = p_strdup(pool, value);

		array_append(&tmpl->args, &key, 1);
		array_append(&tmpl->args, &value, 1);
	}
	return tmpl;
}

bool userdb_static_template_isset(struct userdb_static_template *tmpl,
				  const char *key)
{
	const char *const *args;
	unsigned int i, count;

	args = array_get(&tmpl->args, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (strcmp(args[i], key) == 0)
			return TRUE;
	}
	return FALSE;
}

bool userdb_static_template_remove(struct userdb_static_template *tmpl,
				   const char *key, const char **value_r)
{
	const char *const *args;
	unsigned int i, count;

	args = array_get(&tmpl->args, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (strcmp(args[i], key) == 0) {
			*value_r = args[i+1];
			array_delete(&tmpl->args, i, 2);
			return TRUE;
		}
	}
	return FALSE;
}

void userdb_static_template_export(struct userdb_static_template *tmpl,
				   struct auth_request *auth_request)
{
        const struct var_expand_table *table;
	string_t *str;
	const char *const *args, *value;
	unsigned int i, count;

	str = t_str_new(256);
	table = auth_request_get_var_expand_table(auth_request, NULL);

	args = array_get(&tmpl->args, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (args[i+1] == NULL)
			value = NULL;
		else {
			str_truncate(str, 0);
			var_expand(str, args[i+1], table);
			value = str_c(str);
		}
		auth_request_set_userdb_field(auth_request, args[i], value);
	}
}

struct static_context {
	userdb_callback_t *callback, *old_callback;
	void *old_context;
};

struct static_userdb_module {
	struct userdb_module module;
	struct userdb_static_template *tmpl;

	unsigned int allow_all_users:1;
};

static void static_lookup_real(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct static_userdb_module *module =
		(struct static_userdb_module *)_module;

	auth_request_init_userdb_reply(auth_request);
	userdb_static_template_export(module->tmpl, auth_request);
	callback(USERDB_RESULT_OK, auth_request);
}

static void
static_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials ATTR_UNUSED,
			    size_t size ATTR_UNUSED,
			    struct auth_request *auth_request)
{
	struct static_context *ctx = auth_request->context;

	auth_request->private_callback.userdb = ctx->old_callback;
	auth_request->context = ctx->old_context;
	auth_request_set_state(auth_request, AUTH_REQUEST_STATE_USERDB);

	switch (result) {
	case PASSDB_RESULT_OK:
		static_lookup_real(auth_request, ctx->callback);
		break;
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		ctx->callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		break;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		auth_request_log_error(auth_request, "static",
			"passdb doesn't support lookups, "
			"can't verify user's existence");
		/* fall through */
	default:
		ctx->callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		break;
	}

	i_free(ctx);
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
		auth_request_set_state(auth_request,
				       AUTH_REQUEST_STATE_MECH_CONTINUE);

		auth_request->context = ctx;
		if (auth_request->passdb != NULL) {
			auth_request_lookup_credentials(auth_request, "",
				static_credentials_callback);
		} else {
			static_credentials_callback(
				PASSDB_RESULT_SCHEME_NOT_AVAILABLE,
				NULL, 0, auth_request);
		}
	} else {
		static_lookup_real(auth_request, callback);
	}
}

static struct userdb_module *
static_preinit(pool_t pool, const char *args)
{
	struct static_userdb_module *module;
	const char *value;

	module = p_new(pool, struct static_userdb_module, 1);
	module->tmpl = userdb_static_template_build(pool, "static", args);

	if (userdb_static_template_remove(module->tmpl, "allow_all_users",
					  &value)) {
		module->allow_all_users = value == NULL ||
			strcasecmp(value, "yes") == 0;
	}
	return &module->module;
}

struct userdb_module_interface userdb_static = {
	"static",

	static_preinit,
	NULL,
	NULL,

	static_lookup,

	NULL,
	NULL,
	NULL
};
