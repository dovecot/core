/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_PASSWD_FILE

#include "str.h"
#include "settings.h"
#include "auth-cache.h"
#include "password-scheme.h"
#include "db-passwd-file.h"

struct passwd_file_passdb_module {
	struct passdb_module module;

	struct db_passwd_file *pwf;
};

static int
passwd_file_add_extra_fields(struct auth_request *request,
			     const char *const *fields)
{
	string_t *str = t_str_new(512);
        const struct var_expand_table *table;
	const char *key, *value, *error;
	unsigned int i;
	int ret = 0;

	table = auth_request_get_var_expand_table(request);

	pool_t pool = pool_alloconly_create("passwd-file fields", 256);
	struct auth_fields *pwd_fields = auth_fields_init(pool);
	for (i = 0; fields[i] != NULL; i++) {
		value = strchr(fields[i], '=');
		if (value != NULL) {
			key = t_strdup_until(fields[i], value);
			str_truncate(str, 0);
			if (auth_request_var_expand_with_table(str, value + 1,
					request, table, NULL, &error) < 0) {
				e_error(authdb_event(request),
					"Failed to expand extra field %s: %s",
					fields[i], error);
				ret = -1;
				break;
			}
			value = str_c(str);
		} else {
			key = fields[i];
			value = "";
		}
		if (request->passdb->set->fields_import_all)
			auth_request_set_field(request, key, value, NULL);
		auth_fields_add(pwd_fields, key, value, 0);
	}

	if (ret == 0 && auth_request_set_passdb_fields_ex(request, pwd_fields, "PLAIN",
							  db_passwd_file_var_expand_fn) < 0)
		ret = -1;
	pool_unref(&pool);
	return ret;
}

static int passwd_file_save_results(struct auth_request *request,
				    const struct passwd_user *pu,
				    const char **crypted_pass_r,
				    const char **scheme_r)
{
	*crypted_pass_r = pu->password != NULL ? pu->password : "";
	*scheme_r = password_get_scheme(crypted_pass_r);
	if (*scheme_r == NULL)
		*scheme_r = request->passdb->set->default_password_scheme;

	/* save the password so cache can use it */
	auth_request_set_field(request, "password",
			       *crypted_pass_r, *scheme_r);

	const char *const *extra_fields = pu->extra_fields != NULL ?
		pu->extra_fields : empty_str_array;
	if (passwd_file_add_extra_fields(request, extra_fields) < 0)
		return -1;
	return 0;
}

static void
passwd_file_verify_plain(struct auth_request *request, const char *password,
			 verify_plain_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;
	struct passwd_user *pu;
	const char *scheme, *crypted_pass;
	enum passdb_result result;
        int ret;

	ret = db_passwd_file_lookup(module->pwf, request,
				    request->set->username_format, &pu);
	if (ret <= 0) {
		callback(ret < 0 ? PASSDB_RESULT_INTERNAL_FAILURE :
			 PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (passwd_file_save_results(request, pu, &crypted_pass, &scheme) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	result = auth_request_db_password_verify(request, password,
						 crypted_pass, scheme);

	callback(result, request);
}

static void
passwd_file_lookup_credentials(struct auth_request *request,
			       lookup_credentials_callback_t *callback)
{
	struct passdb_module *_module = request->passdb->passdb;
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;
	struct passwd_user *pu;
	const char *crypted_pass, *scheme;
	int ret;

	ret = db_passwd_file_lookup(module->pwf, request,
				    request->set->username_format, &pu);
	if (ret <= 0) {
		callback(ret < 0 ? PASSDB_RESULT_INTERNAL_FAILURE :
			 PASSDB_RESULT_USER_UNKNOWN, NULL, 0, request);
		return;
	}

	if (passwd_file_save_results(request, pu, &crypted_pass, &scheme) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, NULL, 0, request);
		return;
	}

	passdb_handle_credentials(PASSDB_RESULT_OK, crypted_pass, scheme,
				  callback, request);
}

static int
passwd_file_preinit(pool_t pool, struct event *event,
		    struct passdb_module **module_r, const char **error_r)
{
	struct passwd_file_passdb_module *module;
	const struct passwd_file_settings *set;

	if (settings_get(event, &passwd_file_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	module = p_new(pool, struct passwd_file_passdb_module, 1);
	module->pwf = db_passwd_file_init(set->passwd_file_path, FALSE,
					  global_auth_settings->debug);
	settings_free(set);

	*module_r = &module->module;
	return 0;
}

static void passwd_file_init(struct passdb_module *_module)
{
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;

	db_passwd_file_parse(module->pwf);
}

static void passwd_file_deinit(struct passdb_module *_module)
{
	struct passwd_file_passdb_module *module =
		(struct passwd_file_passdb_module *)_module;

	db_passwd_file_unref(&module->pwf);
}

struct passdb_module_interface passdb_passwd_file = {
	.name = "passwd-file",

	.preinit = passwd_file_preinit,
	.init = passwd_file_init,
	.deinit = passwd_file_deinit,

	.verify_plain = passwd_file_verify_plain,
	.lookup_credentials = passwd_file_lookup_credentials,
};
#else
struct passdb_module_interface passdb_passwd_file = {
	.name = "passwd-file"
};
#endif
