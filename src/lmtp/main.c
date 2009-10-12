/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
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

struct mail_storage_service_multi_ctx *multi_service;

static void client_connected(const struct master_service_connection *conn)
{
	struct client *client;
	void **sets;

	client = client_create(conn->fd, conn->fd);
	client->remote_ip = conn->remote_ip;
	client->remote_port = conn->remote_port;

	sets = master_service_settings_get_others(master_service);
	client->set = sets[1];
	client->lmtp_set = sets[2];

	(void)net_getsockname(conn->fd, &client->local_ip, &client->local_port);
}

static void main_init(void)
{
	if (IS_STANDALONE())
		(void)client_create(STDIN_FILENO, STDOUT_FILENO);
}

static void main_deinit(void)
{
	clients_destroy();
}

int main(int argc, char *argv[], char *envp[])
{
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		&lmtp_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	int c;

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	}

	master_service = master_service_init("lmtp", service_flags, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(master_service, c, optarg))
			exit(FATAL_DEFAULT);
	}

	multi_service = mail_storage_service_multi_init(master_service,
							set_roots,
							storage_service_flags);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	main_init();
	master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_multi_deinit(&multi_service);
	master_service_deinit(&master_service);
	return 0;
}
