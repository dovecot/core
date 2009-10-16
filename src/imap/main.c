/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "base64.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "master-service.h"
#include "master-interface.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "imap-commands.h"
#include "imap-fetch.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv("CLIENT_INPUT") == NULL)

void (*hook_client_created)(struct client **client) = NULL;

static void client_add_input(struct client *client, const char *input)
{
	buffer_t *buf;
	const char *tag;
	unsigned int data_pos;
	bool send_untagged_capability = FALSE;

	buf = input == NULL ? NULL : t_base64_decode_str(input);
	if (buf != NULL && buf->used > 0) {
		tag = t_strndup(buf->data, buf->used);
		switch (*tag) {
		case '0':
			tag++;
			break;
		case '1':
			send_untagged_capability = TRUE;
			tag++;
			break;
		}
		data_pos = strlen(tag) + 1;
		if (data_pos > buf->used &&
		    !i_stream_add_data(client->input,
				       CONST_PTR_OFFSET(buf->data, data_pos),
				       buf->used - data_pos))
			i_panic("Couldn't add client input to stream");
	} else {
		/* IMAPLOGINTAG environment is compatible with mailfront */
		tag = getenv("IMAPLOGINTAG");
	}

	if (tag == NULL) {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY ",
			str_c(client->capability_string), "] "
			"Logged in as ", client->user->username, NULL));
	} else if (send_untagged_capability) {
		/* client doesn't seem to understand tagged capabilities. send
		   untagged instead and hope that it works. */
		o_stream_cork(client->output);
		client_send_line(client, t_strconcat("* CAPABILITY ",
			str_c(client->capability_string), NULL));
		client_send_line(client, t_strconcat(tag, " OK Logged in", NULL));
		o_stream_uncork(client->output);
	} else {
		client_send_line(client, t_strconcat(
			tag, " OK [CAPABILITY ",
			str_c(client->capability_string), "] Logged in", NULL));
	}
	(void)client_handle_input(client);
}

static void main_init(const struct imap_settings *set, struct mail_user *user,
		      bool dump_capability)
{
	struct client *client;
	struct ostream *output;

	if (set->shutdown_clients && !dump_capability)
		master_service_set_die_with_master(master_service, TRUE);

	client = client_create(0, 1, user, set);

	if (dump_capability) {
		printf("%s\n", str_c(client->capability_string));
		exit(0);
	}

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	client_add_input(client, getenv("CLIENT_INPUT"));
        o_stream_uncork(output);
	o_stream_unref(&output);
}

static void main_deinit(void)
{
	clients_destroy_all();
}

static void client_connected(const struct master_service_connection *conn)
{
	/* FIXME: we can't handle this yet */
	(void)close(conn->fd);
}

int main(int argc, char *argv[], char *envp[])
{
	const struct setting_parser_info *set_roots[] = {
		&imap_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STD_CLIENT;
	enum mail_storage_service_flags storage_service_flags = 0;
	struct mail_storage_service_input input;
	struct mail_user *mail_user;
	const struct imap_settings *set;
	bool dump_capability;
	const char *value;
	int c;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("* BAD [ALERT] imap binary must not be started from "
		       "inetd, use imap-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE())
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE;
	else {
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
			MAIL_STORAGE_SERVICE_FLAG_RESTRICT_BY_ENV;
	}

	dump_capability = getenv("DUMP_CAPABILITY") != NULL;
	if (dump_capability) {
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS;
	}

	master_service = master_service_init("imap", service_flags, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(master_service, c, optarg))
			exit(FATAL_DEFAULT);
	}

	memset(&input, 0, sizeof(input));
	input.module = "imap";
	input.service = "imap";
	input.username = getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL) {
		if (getenv(MASTER_UID_ENV) == NULL)
			i_fatal("USER environment missing");
		else {
			i_fatal("login_executable setting must be imap-login, "
				"not imap");
		}
	}
	if ((value = getenv("IP")) != NULL)
		net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		net_addr2ip(value, &input.local_ip);

	/* plugins may want to add commands, so this needs to be called early */
	commands_init();
	imap_fetch_handlers_init();

	mail_user = mail_storage_service_init_user(master_service,
						   &input, set_roots,
						   storage_service_flags);
	set = mail_storage_service_get_settings(master_service);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	/* fake that we're running, so we know if client was destroyed
	   while initializing */
	io_loop_set_running(current_ioloop);

	T_BEGIN {
		main_init(set, mail_user, dump_capability);
	} T_END;
	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_deinit_user();
	imap_fetch_handlers_deinit();
	commands_deinit();

	master_service_deinit(&master_service);
	return 0;
}
