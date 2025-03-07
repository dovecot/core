/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "ioloop.h"
#include "randgen.h"
#include "str.h"
#include "stats-dist.h"
#include "process-title.h"
#include "env-util.h"
#include "module-dir.h"
#include "settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "sql-api.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-commands.h"
#include "dict-connection.h"
#include "dict-settings.h"
#include "dict-init-cache.h"
#include "main.h"

#include <math.h>

static struct module *modules;
static struct timeout *to_proctitle;
static bool proctitle_updated;
static struct ioloop *main_ioloop;

static void
add_stats_string(string_t *str, struct stats_dist *stats, const char *name)
{
	uint64_t min, max, p95;
	double avg;

	min = stats_dist_get_min(stats);
	avg = stats_dist_get_avg(stats);
	p95 = stats_dist_get_95th(stats);
	max = stats_dist_get_max(stats);

	str_printfa(str, ", %u %s:%llu/%lld/%llu/%llu",
		    stats_dist_get_count(stats), name,
		    (unsigned long long)min/1000, llrint(avg/1000),
		    (unsigned long long)p95/1000,
		    (unsigned long long)max/1000);
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
	if (!server_settings->verbose_proctitle)
		return;

	if (to_proctitle == NULL)
		to_proctitle = timeout_add_to(main_ioloop, 1000, dict_proctitle_update, NULL);
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
#ifdef HAVE_CDB
	dict_driver_register(&dict_driver_cdb);
#endif

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	struct event *event = master_service_get_event(master_service);
	struct module_dir_load_settings mod_set;

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
	dict_commands_init();
	dict_connections_init();

	if (server_settings->verbose_proctitle)
		dict_proctitle_update(NULL);
}

static void main_deinit(void)
{
	/* wait for all dict operations to finish */
	dict_init_cache_wait_all();
	/* connections should no longer have any extra refcounts */
	dict_connections_destroy_all();
	dict_init_cache_destroy_all();

	dict_drivers_unregister_all();
	dict_commands_deinit();

	module_dir_unload(&modules);

	sql_drivers_deinit();
	timeout_remove(&to_proctitle);
	settings_free(dict_settings);
	settings_free(server_settings);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags = 0;
	const char *error;

	master_service = master_service_init("dict", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, &error) < 0)
		i_fatal("%s", error);

	master_service_init_log_with_pid(master_service);
	main_preinit();
	master_service_set_die_callback(master_service, dict_die);

	main_ioloop = current_ioloop;
	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	/* clean up cached dicts */
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
