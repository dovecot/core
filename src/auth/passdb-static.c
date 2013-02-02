/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "passdb.h"
#include "passdb-template.h"

struct static_passdb_module {
	struct passdb_module module;
	struct passdb_template *tmpl;
	const char *static_password_tmpl;
};

static void
static_save_fields(struct auth_request *request, const char **password_r)
{
	struct static_passdb_module *module =
		(struct static_passdb_module *)request->passdb->passdb;
        const struct var_expand_table *table;
	string_t *str = t_str_new(128);

	auth_request_log_debug(request, "static", "lookup");
	passdb_template_export(module->tmpl, request);

	if (module->static_password_tmpl == NULL)
		*password_r = "";
	else {
		table = auth_request_get_var_expand_table(request, NULL);
		var_expand(str, module->static_password_tmpl, table);
		*password_r = str_c(str);
	}
}

static void
static_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	const char *static_password;
	int ret;

	static_save_fields(request, &static_password);

	ret = auth_request_password_verify(request, password, static_password,
					   STATIC_PASS_SCHEME, "static");
	if (ret <= 0) {
		callback(PASSDB_RESULT_PASSWORD_MISMATCH, request);
		return;
	}

	callback(PASSDB_RESULT_OK, request);
}

static void
static_lookup_credentials(struct auth_request *request,
			  lookup_credentials_callback_t *callback)
{
	const char *static_password;

	static_save_fields(request, &static_password);
	passdb_handle_credentials(PASSDB_RESULT_OK, static_password,
				  STATIC_PASS_SCHEME, callback, request);
}

static struct passdb_module *
static_preinit(pool_t pool, const char *args)
{
	struct static_passdb_module *module;
	const char *value;

	module = p_new(pool, struct static_passdb_module, 1);
	module->tmpl = passdb_template_build(pool, args);

	if (passdb_template_remove(module->tmpl, "password", &value))
		module->static_password_tmpl = value;
	return &module->module;
}

struct passdb_module_interface passdb_static = {
	"static",

	static_preinit,
	NULL,
	NULL,

	static_verify_plain,
	static_lookup_credentials,
	NULL
};
