/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "randgen.h"
#include "env-util.h"
#include "module-dir.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-connection.h"
#include "dict-settings.h"

static struct module *modules;

static void dict_die(void)
{
	/* hope that other processes relying on us will die first. */
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	dict_connection_create(conn->fd);
}

static void main_preinit(void)
{
	/* Maybe needed. Have to open /dev/urandom before possible
	   chrooting. */
	random_init();

	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	struct module_dir_load_settings mod_set;
	void **sets;

	sets = master_service_settings_get_others(master_service);
	dict_settings = sets[0];

	if (*dict_settings->dict_db_config != '\0') {
		/* for berkeley db library */
		env_put(t_strconcat("DB_CONFIG=", dict_settings->dict_db_config,
				    NULL));
	}

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
	mod_set.require_init_funcs = TRUE;

	modules = module_dir_load(DICT_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	/* Register only after loading modules. They may contain SQL drivers,
	   which we'll need to register. */
	dict_drivers_register_all();
}

static void main_deinit(void)
{
	dict_connections_destroy_all();
	dict_drivers_unregister_all();

	module_dir_unload(&modules);

	sql_drivers_deinit();
	random_deinit();
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&dict_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("dict", 0, &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, "dict: ");
	main_preinit();
	master_service_init_finish(master_service);
	master_service_set_die_callback(master_service, dict_die);

	main_init();
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
