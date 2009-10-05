/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "ioloop.h"
#include "istream.h"
#include "buffer.h"
#include "base64.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-service.h"
#include "master-interface.h"
#include "var-expand.h"
#include "mail-storage-service.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL)

void (*hook_client_created)(struct client **client) = NULL;

static bool main_init(const struct pop3_settings *set, struct mail_user *user)
{
	struct client *client;
	const char *str;
	bool ret = TRUE;

	if (set->shutdown_clients)
		master_service_set_die_with_master(master_service, TRUE);

	client = client_create(0, 1, user, set);
	if (client == NULL)
		return FALSE;

	if (!IS_STANDALONE())
		client_send_line(client, "+OK Logged in.");

	str = getenv("CLIENT_INPUT");
	if (str != NULL) T_BEGIN {
		buffer_t *buf = t_base64_decode_str(str);
		if (buf->used > 0) {
			if (!i_stream_add_data(client->input, buf->data,
					       buf->used))
				i_panic("Couldn't add client input to stream");
			ret = client_handle_input(client);
		}
	} T_END;
	return ret;
}

static void main_deinit(void)
{
	clients_destroy_all();
}

static void client_connected(const struct master_service_connection *conn)
{
	/* we can't handle this yet */
	(void)close(conn->fd);
}

int main(int argc, char *argv[], char *envp[])
{
	const struct setting_parser_info *set_roots[] = {
		&pop3_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STD_CLIENT;
	enum mail_storage_service_flags storage_service_flags = 0;
	struct mail_storage_service_input input;
	struct mail_user *mail_user;
	const struct pop3_settings *set;
	const char *value;
	int c;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("-ERR pop3 binary must not be started from "
		       "inetd, use pop3-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE())
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE;
	else {
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
			MAIL_STORAGE_SERVICE_FLAG_RESTRICT_BY_ENV;
	}

	master_service = master_service_init("pop3", service_flags, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(master_service, c, optarg))
			exit(FATAL_DEFAULT);
	}

	memset(&input, 0, sizeof(input));
	input.module = "pop3";
	input.service = "pop3";
	input.username = getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL) {
		if (getenv(MASTER_UID_ENV) == NULL)
			i_fatal("USER environment missing");
		else {
			i_fatal("login_executable setting must be pop3-login, "
				"not pop3");
		}
	}
	if ((value = getenv("IP")) != NULL)
		net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		net_addr2ip(value, &input.local_ip);

	mail_user = mail_storage_service_init_user(master_service,
						   &input, set_roots,
						   storage_service_flags);
	set = mail_storage_service_get_settings(master_service);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	/* fake that we're running, so we know if client was destroyed
	   while initializing */
	io_loop_set_running(current_ioloop);

	if (main_init(set, mail_user))
		master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_deinit_user();
	master_service_deinit(&master_service);
	return 0;
}
