/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "client.h"
#include "main.h"

#include <stdlib.h>
#include <unistd.h>

#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv("MASTER_SERVICE") == NULL)

struct mail_storage_service_multi_ctx *multi_service;

static void client_connected(const struct master_service_connection *conn)
{
	struct client *client;
	struct ip_addr remote_ip;
	unsigned int remote_port;
	int fd;

	fd = net_accept(conn->fd, &remote_ip, &remote_port);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept() failed: %m");
		return;
	}
	client = client_create(fd, fd);
	client->remote_ip = remote_ip;
	client->remote_port = remote_port;

	(void)net_getsockname(fd, &client->local_ip, &client->local_port);
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
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	int c;

#ifdef DEBUG
	if (!IS_STANDALONE() && getenv("GDB") == NULL) {
		const char *env;

		env = getenv("LISTEN_FDS");
		fd_debug_verify_leaks(LMTP_MASTER_FIRST_LISTEN_FD +
				      (env == NULL ? 0 : atoi(env)), 1024);
	}
#endif

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
