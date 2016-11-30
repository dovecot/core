/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hostpid.h"
#include "path-util.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "anvil-client.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "client.h"
#include "main.h"

#include <unistd.h>

#define DNS_CLIENT_SOCKET_PATH "dns-client"
#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

char *dns_client_socket_path, *base_dir;
struct mail_storage_service_ctx *storage_service;
struct anvil_client *anvil;

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	(void)client_create(conn->fd, conn->fd, conn);
}

static void drop_privileges(void)
{
	struct restrict_access_settings set;
	const char *error;

	/* by default we don't drop any privileges, but keep running as root. */
	restrict_access_get_env(&set);
	/* open config connection before dropping privileges */
	struct master_service_settings_input input;
	struct master_service_settings_output output;

	i_zero(&input);
	input.module = "lmtp";
	input.service = "lmtp";
	(void)master_service_settings_read(master_service,
					   &input, &output, &error);
	restrict_access_by_env(NULL, FALSE);
}

static void main_init(void)
{
	struct master_service_connection conn;

	if (IS_STANDALONE()) {
		i_zero(&conn);
		(void)client_create(STDIN_FILENO, STDOUT_FILENO, &conn);
	}
	dns_client_socket_path = i_strdup(t_abspath(DNS_CLIENT_SOCKET_PATH));
}

static void main_deinit(void)
{
	clients_destroy();
	if (anvil != NULL)
		anvil_client_deinit(&anvil);
	i_free(dns_client_socket_path);
	i_free(base_dir);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		&lmtp_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
		MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT |
		MAIL_STORAGE_SERVICE_FLAG_AUTOEXPUNGE;
	const char *tmp_base_dir;
	int c;

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN  ;
	}

	master_service = master_service_init("lmtp", service_flags,
					     &argc, &argv, "D");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			storage_service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	if (t_get_current_dir(&tmp_base_dir) < 0)
		i_fatal("getcwd() failed: %m");
	base_dir = i_strdup(tmp_base_dir);

	drop_privileges();
	master_service_init_log(master_service,
				t_strdup_printf("lmtp(%s): ", my_pid));

	storage_service = mail_storage_service_init(master_service, set_roots,
						    storage_service_flags);
	restrict_access_allow_coredumps(TRUE);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
