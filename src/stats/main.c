/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-server-connection.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "client.h"

struct stats_settings set;
static struct mail_server_connection *mail_server_conn = NULL;

static void client_connected(struct master_service_connection *conn)
{
	if (conn->fifo) {
		if (mail_server_conn != NULL) {
			i_error("Received another mail-server connection");
			return;
		}
		mail_server_conn = mail_server_connection_create(conn->fd);
	} else {
		(void)client_create(conn->fd);
	}
	master_service_client_connection_accept(conn);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&stats_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
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

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	sets = master_service_settings_get_others(master_service);
	stats_settings = sets[0];

	mail_commands_init();
	mail_sessions_init();
	mail_users_init();
	mail_domains_init();
	mail_ips_init();

	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	clients_destroy_all();
	mail_commands_deinit();
	mail_sessions_deinit();
	mail_users_deinit();
	mail_domains_deinit();
	mail_ips_deinit();

	if (mail_server_conn != NULL)
		mail_server_connection_destroy(&mail_server_conn);

	i_assert(global_used_memory == 0);
	master_service_deinit(&master_service);
        return 0;
}
