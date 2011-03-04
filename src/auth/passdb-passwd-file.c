/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_PASSWD_FILE

#include "str.h"
#include "auth-cache.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-passwd-file.h"

struct passwd_file_passdb_module {
	struct passdb_module module;

	struct db_passwd_file *pwf;
	const char *username_format;
};

static void passwd_file_save_results(struct auth_request *request,
				     const struct passwd_user *pu,
				     const char **crypted_pass_r,
				     const char **scheme_r)
{
        const struct var_expand_table *table;
	const char *key, *value;
	string_t *str;
	char **p;

	*crypted_pass_r = pu->password;
	*scheme_r = password_get_scheme(crypted_pass_r);
	if (*scheme_r == NULL)
		*scheme_r = request->passdb->passdb->default_pass_scheme;

	/* save the password so cache can use it */
	if (*crypted_pass_r != NULL) {
		auth_request_set_field(request, "password",
				       *crypted_pass_r, *scheme_r);
        }

	if (pu->extra_fields != NULL) {
		str = t_str_new(512);
		table = auth_request_get_var_expand_table(request, NULL);

		for (p = pu->extra_fields; *p != NULL; p++) {
			value = strchr(*p, '=');
			if (value != NULL) {
				key = t_strdup_until(*p, value);
				str_truncate(str, 0);
				var_expand(str, value + 1, table);
				value = str_c(str);
			} else {
				key = *p;
				value = "";
			}
			auth_request_set_field(request, key, value, NULL);
		}
	}
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
        int ret;

	pu = db_passwd_file_lookup(module->pwf, request,
				   module->username_format);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	passwd_file_save_results(request, pu, &crypted_pass, &scheme);

	ret = auth_request_password_verify(request, password, crypted_pass,
					   scheme, "passwd-file");

	callback(ret > 0 ? PASSDB_RESULT_OK : PASSDB_RESULT_PASSWORD_MISMATCH,
		 request);
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

	pu = db_passwd_file_lookup(module->pwf, request,
				   module->username_format);
	if (pu == NULL) {
		callback(PASSDB_RESULT_USER_UNKNOWN, NULL, 0, request);
		return;
	}

	passwd_file_save_results(request, pu, &crypted_pass, &scheme);

	passdb_handle_credentials(PASSDB_RESULT_OK, crypted_pass, scheme,
				  callback, request);
}

static struct passdb_module *
passwd_file_preinit(pool_t pool, const char *args)
{
	struct passwd_file_passdb_module *module;
	const char *scheme = PASSWD_FILE_DEFAULT_SCHEME;
	const char *format = PASSWD_FILE_DEFAULT_USERNAME_FORMAT;
	const char *key, *value;

	while (*args != '\0') {
		if (*args == '/')
			break;

		key = args;
		value = strchr(key, '=');
		if (value == NULL) {
			value = "";
			args = strchr(key, ' ');
		} else {
			key = t_strdup_until(key, value);
			args = strchr(++value, ' ');
			if (args != NULL)
				value = t_strdup_until(value, args);
		}
		if (args == NULL)
			args = "";
		else
			args++;

		if (strcmp(key, "scheme") == 0)
			scheme = p_strdup(pool, value);
		else if (strcmp(key, "username_format") == 0)
			format = p_strdup(pool, value);
		else
			i_fatal("passdb passwd-file: Unknown setting: %s", key);
	}

	if (*args == '\0')
		i_fatal("passdb passwd-file: Missing args");

	module = p_new(pool, struct passwd_file_passdb_module, 1);
	module->pwf = db_passwd_file_init(args, FALSE,
					  global_auth_settings->debug);
	module->username_format = format;

	if (!module->pwf->vars)
		module->module.cache_key = format;
	else {
		module->module.cache_key = auth_cache_parse_key(pool,
			t_strconcat(format, module->pwf->path, NULL));
	}

	module->module.default_pass_scheme = scheme;
	return &module->module;
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
	"passwd-file",

	passwd_file_preinit,
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_verify_plain,
	passwd_file_lookup_credentials,
	NULL
};
#else
struct passdb_module_interface passdb_passwd_file = {
	.name = "passwd-file"
};
#endif
