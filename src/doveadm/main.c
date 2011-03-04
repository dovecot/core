/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings-parser.h"
#include "client-connection.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "doveadm-print-private.h"
#include "doveadm-server.h"

const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_server_vfuncs,
	NULL
};

struct client_connection *doveadm_client;

int doveadm_mail_server_user(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			     struct mail_storage_service_user *user ATTR_UNUSED,
			     const char **error_r ATTR_UNUSED)
{
	/* this function should be called only by doveadm client code */
	i_unreached();
}
void doveadm_mail_server_flush(void)
{
}

static void doveadm_die(void)
{
	/* do nothing. doveadm connections should be over soon. */
}

static void client_connected(struct master_service_connection *conn)
{
	if (doveadm_client != NULL) {
		i_error("doveadm server can handle only a single client");
		return;
	}

	master_service_client_connection_accept(conn);
	doveadm_client = client_connection_create(conn->fd, conn->listen_fd);
}

static void main_preinit(void)
{
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	doveadm_server = TRUE;
	doveadm_settings = master_service_settings_get_others(master_service)[0];
	doveadm_settings = settings_dup(&doveadm_setting_parser_info,
					doveadm_settings,
					pool_datastack_create());

	doveadm_mail_init();
	doveadm_load_modules();
	doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
}

static void main_deinit(void)
{
	if (doveadm_client != NULL)
		client_connection_destroy(&doveadm_client);
	doveadm_mail_deinit();
	doveadm_unload_modules();
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("doveadm", 0, &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, "doveadm: ");
	main_preinit();
	master_service_init_finish(master_service);
	master_service_set_die_callback(master_service, doveadm_die);

	main_init();
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
