/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-service.h"
#include "settings-parser.h"
#include "dict.h"
#include "doveadm.h"
#include "client-connection.h"
#include "client-connection-private.h"
#include "doveadm-settings.h"
#include "doveadm-dump.h"
#include "doveadm-mail.h"
#include "doveadm-print-private.h"
#include "ostream.h"

const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_server_vfuncs,
	&doveadm_print_json_vfuncs,
	NULL
};

struct client_connection *doveadm_client;
int doveadm_exit_code = 0;

static void doveadm_die(void)
{
	/* do nothing. doveadm connections should be over soon. */
}

static void client_connected(struct master_service_connection *conn)
{
	const char *type;

	if (doveadm_client != NULL) {
		i_error("doveadm server can handle only a single client");
		return;
	}

	master_service_client_connection_accept(conn);
	type = master_service_connection_get_type(conn);
	if (strcmp(type, "http") == 0) {
		doveadm_client = client_connection_http_create(conn->fd, conn->ssl);
	} else {
		doveadm_client = client_connection_tcp_create(conn->fd, conn->listen_fd,
							  conn->ssl);
	}
}

void help_ver2(const struct doveadm_cmd_ver2 *cmd)
{
	i_fatal("Client sent invalid command. Usage: %s %s",
		cmd->name, cmd->usage);
}

static void main_preinit(void)
{
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	doveadm_server = TRUE;

	doveadm_settings_init();
	doveadm_cmds_init();
	doveadm_register_auth_server_commands();
	doveadm_dump_init();
	doveadm_mail_init();
	dict_drivers_register_builtin();
	doveadm_load_modules();
	/* read settings only after loading doveadm plugins, which
	   may modify what settings are read */
	doveadm_read_settings();
	/* Load mail_plugins */
	doveadm_mail_init_finish();
	/* kludgy: Load the rest of the doveadm plugins after
	   mail_plugins have been loaded. */
	doveadm_load_modules();

	doveadm_server_init();
	if (doveadm_verbose_proctitle)
		process_title_set("[idling]");
}

static void main_deinit(void)
{
	doveadm_server_deinit();
	doveadm_mail_deinit();
	doveadm_dump_deinit();
	doveadm_unload_modules();
	dict_drivers_unregister_builtin();
	doveadm_print_deinit();
	doveadm_cmds_deinit();
	doveadm_settings_deinit();
}

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_HAVE_STARTTLS;
	int c;

	master_service = master_service_init("doveadm", service_flags,
					     &argc, &argv, "D");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	master_service_init_log(master_service);
	main_preinit();
	master_service_set_die_callback(master_service, doveadm_die);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
