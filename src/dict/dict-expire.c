/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "restrict-access.h"
#include "ioloop.h"
#include "process-title.h"
#include "env-util.h"
#include "module-dir.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-settings.h"

#define DICT_EXPIRE_RUN_INTERVAL_MSECS (30*1000)

struct expire_dict {
	const char *name;
	struct dict *dict;
};

static struct module *modules;
static struct timeout *to_expire;
static ARRAY(struct expire_dict) expire_dicts;

static void dict_expire_run(void)
{
	struct expire_dict *dicts;
	unsigned int i, count;
	const char *error;
	int ret;

	dicts = array_get_modifiable(&expire_dicts, &count);
	for (i = count; i > 0; i--) {
		struct expire_dict *dict = &dicts[i-1];

		if (dict_settings->verbose_proctitle)
			process_title_set(t_strdup_printf("[running dict %s]", dict->name));
		ret = dict_expire_scan(dict->dict, &error);
		if (ret < 0)
			i_error("Expire run failed: %s", error);
		else if (ret == 0) {
			dict_deinit(&dict->dict);
			array_delete(&expire_dicts, i-1, 1);
		}
	}
	if (dict_settings->verbose_proctitle)
		process_title_set("[idling]");
}

static void dict_expire_timeout(void *context ATTR_UNUSED)
{
	dict_expire_run();
}

static void client_connected(struct master_service_connection *conn ATTR_UNUSED)
{
	/* This service doesn't support any clients. However, for testing
	   purposes, if a client attempts to connect to any socket, we'll
	   trigger immediate expire run. */
	dict_expire_run();
}

static void dict_expire_init(void)
{
	struct dict_settings dict_set = {
		.base_dir = dict_settings->base_dir,
	};
	struct dict *dict;
	const char *const *strlist, *error;
	unsigned int i, count;

	i_array_init(&expire_dicts, 16);
	strlist = array_get(&dict_settings->dicts, &count);
	for (i = 0; i < count; i += 2) {
		const char *name = strlist[i];
		const char *uri = strlist[i+1];

		if (dict_init(uri, &dict_set, &dict, &error) < 0) {
			i_error("Failed to initialize dictionary '%s': %s - skipping",
				name, error);
		} else {
			struct expire_dict *expire_dict =
				array_append_space(&expire_dicts);
			expire_dict->name = name;
			expire_dict->dict = dict;
		}
	}
}

static void main_preinit(void)
{
	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();
#ifdef HAVE_CDB
	dict_driver_register(&dict_driver_cdb);
#endif

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	struct module_dir_load_settings mod_set;

	dict_settings = master_service_settings_get_root_set(master_service,
				&dict_setting_parser_info);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;

	modules = module_dir_load(DICT_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	/* Register only after loading modules. They may contain SQL drivers,
	   which we'll need to register. */
	dict_drivers_register_all();

	dict_expire_init();
	to_expire = timeout_add(DICT_EXPIRE_RUN_INTERVAL_MSECS,
				dict_expire_timeout, NULL);
}

static void main_deinit(void)
{
	struct expire_dict *dict;

	array_foreach_modifiable(&expire_dicts, dict)
		dict_deinit(&dict->dict);
	array_free(&expire_dicts);

	dict_drivers_unregister_all();
	module_dir_unload(&modules);

	sql_drivers_deinit();
	timeout_remove(&to_expire);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags = 0;
	const struct setting_parser_info *set_roots[] = {
		&dict_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("dict-expire", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	const struct master_service_settings_input set_input = {
		.roots = set_roots,
	};
	struct master_service_settings_output output;
	if (master_service_settings_read(master_service, &set_input,
					 &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log_with_pid(master_service);
	main_preinit();

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
