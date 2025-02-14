/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "password-scheme.h"
#include "settings.h"
#include "auth-settings.h"

static enum passdb_result
static_save_fields(struct auth_request *request, const char **password_r,
		   const char **scheme_r)
{
	const struct auth_static_settings *set;
	const char *error;

	*password_r = NULL;
	*scheme_r = NULL;

	e_debug(authdb_event(request), "lookup");
	if (settings_get(authdb_event(request),
			 &auth_static_setting_parser_info, 0, &set,
			 &error) < 0)
		return -1;
	if (auth_request_set_passdb_fields(request, NULL) < 0) {
		settings_free(set);
		return PASSDB_RESULT_INTERNAL_FAILURE;
	}
	if (set->passdb_static_password[0] != '\0') {
		*password_r = p_strdup(request->pool, set->passdb_static_password);
	} else if (auth_fields_exists(request->fields.extra_fields, "nopassword")) {
		*password_r = "";
	} else {
		settings_free(set);
		return auth_request_password_missing(request);
	}

	settings_free(set);
	*scheme_r = password_get_scheme(password_r);

	if (*scheme_r == NULL)
		*scheme_r = STATIC_PASS_SCHEME;

	auth_request_set_field(request, "password",
			       *password_r, *scheme_r);

	return PASSDB_RESULT_OK;
}

static void
static_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	enum passdb_result result;
	const char *static_password;
	const char *static_scheme;

	result = static_save_fields(request, &static_password, &static_scheme);
	if (result != PASSDB_RESULT_OK) {
		callback(result, request);
		return;
	}

	result = auth_request_db_password_verify(
		request, password, static_password, static_scheme);
	callback(result, request);
}

static void
static_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	enum passdb_result result;
	const char *static_password;
	const char *static_scheme;

	result = static_save_fields(request, &static_password, &static_scheme);
	passdb_handle_credentials(result, static_password,
				  static_scheme, callback, request);
}

struct passdb_module_interface passdb_static = {
	.name = "static",

	.verify_plain = static_verify_plain,
	.lookup_credentials = static_lookup_credentials,
};
