/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "fifo-input-connection.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "mail-stats.h"
#include "client.h"

static struct module *modules = NULL;

static void client_connected(struct master_service_connection *conn)
{
	if (conn->fifo)
		(void)fifo_input_connection_create(conn->fd);
	else
		(void)client_create(conn->fd);
	master_service_client_connection_accept(conn);
}

static void main_preinit(void)
{
	struct module_dir_load_settings mod_set;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;

	modules = module_dir_load(STATS_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&old_stats_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_IDLE_DIE |
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;
	void **sets;

	master_service = master_service_init("stats", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "stats: ");

	main_preinit();

	sets = master_service_settings_get_others(master_service);
	stats_settings = sets[0];

	mail_commands_init();
	mail_sessions_init();
	mail_users_init();
	mail_domains_init();
	mail_ips_init();
	mail_global_init();

	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	clients_destroy_all();
	fifo_input_connections_destroy_all();
	mail_commands_deinit();
	mail_sessions_deinit();
	mail_users_deinit();
	mail_domains_deinit();
	mail_ips_deinit();
	mail_global_deinit();

	module_dir_unload(&modules);
	i_assert(global_used_memory == 0);
	master_service_deinit(&master_service);
        return 0;
}
