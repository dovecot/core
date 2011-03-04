/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "passdb.h"

#define STATIC_PASS_SCHEME "PLAIN"

struct static_passdb_module {
	struct passdb_module module;
	ARRAY_TYPE(const_string) tmpl;
};

static void
static_save_fields(struct auth_request *request, const char **password_r)
{
	struct static_passdb_module *module =
		(struct static_passdb_module *)request->passdb->passdb;
        const struct var_expand_table *table;
	const char *const *args;
	unsigned int i, count;
	string_t *str = t_str_new(128);

	auth_request_log_debug(request, "static", "lookup");

	table = auth_request_get_var_expand_table(request, NULL);

	*password_r = "";
	args = array_get(&module->tmpl, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		const char *key = args[i];
		const char *value = args[i+1];

		if (value != NULL) {
			str_truncate(str, 0);
			var_expand(str, args[i+1], table);
			value = str_c(str);
		}

		if (strcmp(key, "password") == 0)
			*password_r = value;
		else {
			auth_request_set_field(request, key, value,
					       STATIC_PASS_SCHEME);
		}
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

	module = p_new(pool, struct static_passdb_module, 1);
	p_array_init(&module->tmpl, pool, 16);
	T_BEGIN {
		const char *const *tmp;

		tmp = t_strsplit_spaces(args, " ");
		for (; *tmp != NULL; tmp++) {
			const char *key = *tmp;
			const char *value = strchr(key, '=');

			if (value == NULL)
				value = "";
			else
				key = t_strdup_until(key, value++);

			key = p_strdup(pool, key);
			value = p_strdup(pool, value);
			array_append(&module->tmpl, &key, 1);
			array_append(&module->tmpl, &value, 1);
		}
	} T_END;
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
