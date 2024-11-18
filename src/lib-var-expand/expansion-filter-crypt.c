/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "var-expand-private.h"
#include "expansion.h"

static struct module *var_expand_crypt_module;

static var_expand_filter_func_t *fn_encrypt = NULL;
static var_expand_filter_func_t *fn_decrypt = NULL;

void var_expand_crypt_load(void)
{
	struct module_dir_load_settings set = {
		.require_init_funcs = TRUE
	};
	const char *const mods[] = {
		"var_expand_crypt",
		NULL
	};

	var_expand_crypt_module =
		module_dir_load(VAR_EXPAND_MODULE_DIR, mods, &set);
	module_dir_init(var_expand_crypt_module);
}

void expansion_filter_crypt_set_functions(var_expand_filter_func_t *encrypt,
					  var_expand_filter_func_t *decrypt)
{
	i_assert(fn_encrypt == NULL && fn_decrypt == NULL);
	fn_encrypt = encrypt;
	fn_decrypt = decrypt;
}

int
expansion_filter_encrypt(const struct var_expand_statement *stmt,
			 struct var_expand_state *state, const char **error_r)
{
	if (fn_encrypt == NULL)
		var_expand_crypt_load();
	return fn_encrypt(stmt, state, error_r);
}

int
expansion_filter_decrypt(const struct var_expand_statement *stmt,
			 struct var_expand_state *state, const char **error_r)
{
	if (fn_decrypt == NULL)
		var_expand_crypt_load();
	return fn_decrypt(stmt, state, error_r);
}
