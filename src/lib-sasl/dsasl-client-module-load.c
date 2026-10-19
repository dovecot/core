/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "dsasl-client-private.h"

/* This is in its own file so that unit tests can replace the function with
   their own, without linking the rest of the module handling twice. */
int dsasl_client_module_load(struct dsasl_client *client,
			     const struct dsasl_client_module *module,
			     const char **error_r)
{
	const char *const module_names[] = { module->name, NULL };
	const struct module_dir_load_settings mod_set = {
		.abi_version = DOVECOT_ABI_VERSION,
	};
	void (*init_func)(struct dsasl_client *);
	struct module *mod;
	const char *error;

	if (module_dir_try_load_missing(&client->modules, MODULE_DIR,
					module_names, &mod_set, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to load SASL mechanism module %s from %s: %s",
			module->name, MODULE_DIR, error);
		return -1;
	}
	mod = module_dir_find(client->modules, module->name);
	i_assert(mod != NULL);

	init_func = (void (*)(struct dsasl_client *))
		module_get_symbol_quiet(mod, module->init_symbol);
	if (init_func == NULL) {
		*error_r = t_strdup_printf(
			"SASL mechanism module %s doesn't have %s()",
			module->name, module->init_symbol);
		return -1;
	}
	init_func(client);
	return 0;
}
