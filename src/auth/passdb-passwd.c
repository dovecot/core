/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "auth-cache.h"
#include "passdb.h"
#include "settings.h"

#ifdef PASSDB_PASSWD

#include "safe-memset.h"
#include "ipwd.h"

#define PASSWD_CACHE_KEY "%u"
#define PASSWD_PASS_SCHEME "CRYPT"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_passwd_settings)

struct auth_passwd_settings {
	pool_t pool;
};

static const struct setting_define auth_passwd_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_passwd", },
	{ .type = SET_FILTER_NAME, .key = "userdb_passwd", },

	SETTING_DEFINE_LIST_END
};

static const struct setting_keyvalue auth_passwd_default_settings_keyvalue[] = {
	{ "passdb_passwd/passdb_use_worker", "yes" },
	{ "passdb_passwd/passdb_default_password_scheme", "crypt" },
	{ "userdb_passwd/userdb_use_worker", "yes" },
	{ NULL, NULL }
};

const struct setting_parser_info auth_passwd_info = {
	.name = "passwd",

	.defines = auth_passwd_setting_defines,
	.default_settings = auth_passwd_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_passwd_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passwd_settings, pool),
};

static enum passdb_result
passwd_lookup(struct auth_request *request, struct passwd *pw_r)
{
	e_debug(authdb_event(request), "lookup");

	if (auth_request_set_passdb_fields(request, NULL) < 0)
		return PASSDB_RESULT_INTERNAL_FAILURE;

	switch (i_getpwnam(request->fields.user, pw_r)) {
	case -1:
		e_error(authdb_event(request),
			"getpwnam() failed: %m");
		return PASSDB_RESULT_INTERNAL_FAILURE;
	case 0:
		auth_request_db_log_unknown_user(request);
		return PASSDB_RESULT_USER_UNKNOWN;
	}

	if (!IS_VALID_PASSWD(pw_r->pw_passwd)) {
		e_info(authdb_event(request),
		       "invalid password field '%s'", pw_r->pw_passwd);
		return PASSDB_RESULT_USER_DISABLED;
	}

	/* save the password so cache can use it */
	auth_request_set_field(request, "password", pw_r->pw_passwd,
			       PASSWD_PASS_SCHEME);
	return PASSDB_RESULT_OK;
}

static void
passwd_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct passwd pw;
	enum passdb_result res;

	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	res = passwd_lookup(request, &pw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, request);
		return;
	}
	/* check if the password is valid */
	res = auth_request_db_password_verify(request, password, pw.pw_passwd,
					      PASSWD_PASS_SCHEME);

	/* clear the passwords from memory */
	safe_memset(pw.pw_passwd, 0, strlen(pw.pw_passwd));

	if (res != PASSDB_RESULT_OK) {
		callback(res, request);
		return;
	}

	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw.pw_name, NULL);

	callback(res, request);
}

static void
passwd_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	struct passwd pw;
	enum passdb_result res;

	res = passwd_lookup(request, &pw);
	if (res != PASSDB_RESULT_OK) {
		callback(res, NULL, 0, request);
		return;
	}
	/* make sure we're using the username exactly as it's in the database */
        auth_request_set_field(request, "user", pw.pw_name, NULL);
	passdb_handle_credentials(PASSDB_RESULT_OK, pw.pw_passwd,
				  PASSWD_PASS_SCHEME, callback, request);
}

static int passwd_preinit(pool_t pool, struct event *event,
			  struct passdb_module **module_r,
			  const char **error_r )
{
	const struct auth_passdb_post_settings *post_set;
	struct passdb_module *module = p_new(pool, struct passdb_module, 1);

	if (settings_get(event,
			 &auth_passdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &post_set, error_r) < 0)
		return -1;
	module->default_cache_key = auth_cache_parse_key_and_fields(pool,
								    PASSWD_CACHE_KEY,
								    &post_set->fields,
								    "passwd");
	settings_free(post_set);
	*module_r = module;
	return 0;
}

static void passwd_deinit(struct passdb_module *module ATTR_UNUSED)
{
	endpwent();
}

struct passdb_module_interface passdb_passwd = {
	.name = "passwd",

	.preinit = passwd_preinit,
	.deinit = passwd_deinit,

	.verify_plain = passwd_verify_plain,
	.lookup_credentials = passwd_lookup_credentials,
};

#else
struct passdb_module_interface passdb_passwd = {
	.name = "passwd"
};
#endif
