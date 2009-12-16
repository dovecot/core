/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hostpid.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "client.h"
#include "main.h"

#include <stdlib.h>
#include <unistd.h>

#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv(MASTER_UID_ENV) == NULL)

struct mail_storage_service_ctx *storage_service;

static void client_connected(const struct master_service_connection *conn)
{
	(void)client_create(conn->fd, conn->fd, conn);
}

static void main_init(void)
{
	struct master_service_connection conn;

	if (IS_STANDALONE()) {
		memset(&conn, 0, sizeof(conn));
		(void)client_create(STDIN_FILENO, STDOUT_FILENO, &conn);
	}
}

static void main_deinit(void)
{
	clients_destroy();
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		&lmtp_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
		MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT;
	int c;

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
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
	master_service_init_finish(master_service);
	master_service_init_log(master_service,
				t_strdup_printf("lmtp(%s): ", my_pid));

	storage_service = mail_storage_service_init(master_service, set_roots,
						    storage_service_flags);
	restrict_access_allow_coredumps(TRUE);

	main_init();
	master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
