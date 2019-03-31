/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "ioloop.h"
#include "randgen.h"
#include "str.h"
#include "hostpid.h"
#include "stats-dist.h"
#include "process-title.h"
#include "env-util.h"
#include "module-dir.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-commands.h"
#include "dict-connection.h"
#include "dict-settings.h"
#include "main.h"

static struct module *modules;
static struct timeout *to_proctitle;
static bool proctitle_updated;

static void
add_stats_string(string_t *str, struct stats_dist *stats, const char *name)
{
	str_printfa(str, ", %u %s:%"PRIu64"/%.02f/%"PRIu64"/%"PRIu64,
		    stats_dist_get_count(stats), name,
		    stats_dist_get_min(stats)/1000, stats_dist_get_avg(stats)/1000,
		    stats_dist_get_95th(stats)/1000, stats_dist_get_max(stats)/1000);
	stats_dist_reset(stats);
}

static void dict_proctitle_update(void *context ATTR_UNUSED)
{
	string_t *str = t_str_new(128);

	if (!proctitle_updated)
		timeout_remove(&to_proctitle);

	str_printfa(str, "[%u clients", dict_connections_current_count());

	add_stats_string(str, cmd_stats.lookups, "lookups");
	add_stats_string(str, cmd_stats.iterations, "iters");
	add_stats_string(str, cmd_stats.commits, "commits");
	str_append_c(str, ']');

	process_title_set(str_c(str));
	proctitle_updated = FALSE;
}

void dict_proctitle_update_later(void)
{
	if (!dict_settings->verbose_proctitle)
		return;

	if (to_proctitle == NULL)
		to_proctitle = timeout_add(1000, dict_proctitle_update, NULL);
	proctitle_updated = TRUE;
}

static void dict_die(void)
{
	/* hope that other processes relying on us will die first. */
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	(void)dict_connection_create(conn);
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
	void **sets;

	sets = master_service_settings_get_others(master_service);
	dict_settings = sets[0];

	if (*dict_settings->dict_db_config != '\0') {
		/* for berkeley db library */
		env_put(t_strconcat("DB_CONFIG=", dict_settings->dict_db_config,
				    NULL));
	}

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;

	modules = module_dir_load(DICT_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	/* Register only after loading modules. They may contain SQL drivers,
	   which we'll need to register. */
	dict_drivers_register_all();
	dict_commands_init();
	dict_connections_init();
}

static void main_deinit(void)
{
	timeout_remove(&to_proctitle);

	dict_connections_destroy_all();
	dict_drivers_unregister_all();
	dict_commands_deinit();

	module_dir_unload(&modules);

	sql_drivers_deinit();
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags = 0;
	const struct setting_parser_info *set_roots[] = {
		&dict_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("dict", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, t_strdup_printf("dict(%s): ", my_pid));
	main_preinit();
	master_service_set_die_callback(master_service, dict_die);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
