/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "restrict-access.h"
#include "ioloop.h"
#include "process-title.h"
#include "env-util.h"
#include "module-dir.h"
#include "settings.h"
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

		if (server_settings->verbose_proctitle)
			process_title_set(t_strdup_printf("[running dict %s]", dict->name));
		ret = dict_expire_scan(dict->dict, &error);
		if (ret < 0)
			i_error("Expire run failed: %s", error);
		else if (ret == 0) {
			dict_deinit(&dict->dict);
			array_delete(&expire_dicts, i-1, 1);
		}
	}
	if (server_settings->verbose_proctitle)
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

static void dict_expire_init(struct event *event)
{
	i_array_init(&expire_dicts, 16);

	if (!array_is_created(&dict_settings->dicts))
		return;

	struct dict *dict;
	const char *dict_name, *error;
	array_foreach_elem(&dict_settings->dicts, dict_name) {
		if (dict_init_filter_auto(event, dict_name, &dict, &error) < 0) {
			i_error("Failed to initialize dictionary '%s': %s - skipping",
				dict_name, error);
		} else {
			struct expire_dict *expire_dict =
				array_append_space(&expire_dicts);
			expire_dict->name = dict_name;
			expire_dict->dict = dict;
		}
	}

}

static void main_preinit(void)
{
	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
#ifdef HAVE_CDB
	dict_driver_register(&dict_driver_cdb);
#endif

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	struct module_dir_load_settings mod_set;
	struct event *event = master_service_get_event(master_service);

	event_add_category(event, &dict_server_event_category);
	settings_event_add_filter_name(event, "dict_server");
	server_settings =
		settings_get_or_fatal(event, &dict_server_setting_parser_info);
	dict_settings =
		settings_get_or_fatal(event, &dict_setting_parser_info);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;

	modules = module_dir_load(DICT_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	/* Register only after loading modules. They may contain SQL drivers,
	   which we'll need to register. */
	dict_drivers_register_all();

	dict_expire_init(event);
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
	settings_free(server_settings);
	settings_free(dict_settings);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags = 0;
	const char *error;

	master_service = master_service_init("dict-expire", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, &error) < 0)
		i_fatal("%s", error);

	master_service_init_log_with_pid(master_service);
	main_preinit();

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
