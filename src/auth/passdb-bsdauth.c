/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_BSDAUTH

#include "safe-memset.h"
#include "auth-cache.h"
#include "ipwd.h"
#include "mycrypt.h"
#include "settings.h"

#include <login_cap.h>
#include <bsd_auth.h>

#define BSDAUTH_CACHE_KEY "%u"

struct passdb_bsdauth_settings {
	pool_t pool;
};

static const struct setting_define passdb_bsdauth_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_bsdauth" },

	SETTING_DEFINE_LIST_END,
};

static const struct setting_keyvalue passdb_bsdauth_settings_keyvalue[] = {
	{ "passdb_bsdauth/passdb_use_worker", "yes"},
	{ NULL, NULL }
};

const struct setting_parser_info passdb_bsdauth_setting_parser_info = {
	.name = "auth_bsdauth",

	.defines = passdb_bsdauth_setting_defines,
	.default_settings = passdb_bsdauth_settings_keyvalue,

	.struct_size = sizeof(struct passdb_bsdauth_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_bsdauth_settings, pool),
};

static void
bsdauth_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd pw;
	const char *type;
	int result;

	e_debug(authdb_event(request), "lookup");

	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	switch (i_getpwnam(request->fields.user, &pw)) {
	case -1:
		e_error(authdb_event(request),
			"getpwnam() failed: %m");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	case 0:
		auth_request_db_log_unknown_user(request);
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	/* check if the password is valid */
	type = t_strdup_printf("auth-%s", request->fields.protocol);
	result = auth_userokay(request->fields.user, NULL,
			       t_strdup_noconst(type),
			       t_strdup_noconst(password));

	/* clear the passwords from memory */
	safe_memset(pw.pw_passwd, 0, strlen(pw.pw_passwd));

	if (result == 0) {
		auth_request_db_log_password_mismatch(request);
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw.pw_name, NULL);

	callback(PASSDB_RESULT_OK, request);
}

static int
bsdauth_preinit(pool_t pool, struct event *event,
		struct passdb_module **module_r,
		const char **error_r)
{
	const struct auth_passdb_post_settings *post_set;
	struct passdb_module *module;

	module = p_new(pool, struct passdb_module, 1);
	if (settings_get(event, &auth_passdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &post_set, error_r) < 0)
		return -1;
	module->default_cache_key = auth_cache_parse_key_and_fields(
		pool, BSDAUTH_CACHE_KEY, &post_set->fields, "bsdauth");

	settings_free(post_set);
	*module_r = module;
	return 0;
}

static void bsdauth_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_bsdauth = {
	.name = "bsdauth",

	.preinit = bsdauth_preinit,
	.deinit = bsdauth_deinit,
	.verify_plain = bsdauth_verify_plain,
};
#else
struct passdb_module_interface passdb_bsdauth = {
	.name = "bsdauth"
};
#endif
