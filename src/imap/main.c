/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "base64.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-login.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "imap-commands.h"
#include "imap-fetch.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv(MASTER_UID_ENV) == NULL)

static const struct setting_parser_info *set_roots[] = {
	&imap_setting_parser_info,
	NULL
};
static struct master_login *master_login = NULL;
static enum mail_storage_service_flags storage_service_flags = 0;
static bool user_initialized = FALSE;

void (*hook_client_created)(struct client **client) = NULL;

static void client_add_input(struct client *client, const buffer_t *buf)
{
	struct ostream *output;
	const char *tag;
	unsigned int data_pos;
	bool send_untagged_capability = FALSE;

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

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	if (tag == NULL) {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY ",
			str_c(client->capability_string), "] "
			"Logged in as ", client->user->username, NULL));
	} else if (send_untagged_capability) {
		/* client doesn't seem to understand tagged capabilities. send
		   untagged instead and hope that it works. */
		client_send_line(client, t_strconcat("* CAPABILITY ",
			str_c(client->capability_string), NULL));
		client_send_line(client, t_strconcat(tag, " OK Logged in", NULL));
	} else {
		client_send_line(client, t_strconcat(
			tag, " OK [CAPABILITY ",
			str_c(client->capability_string), "] Logged in", NULL));
	}
	(void)client_handle_input(client);
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static void
main_stdio_init_user(const struct imap_settings *set, struct mail_user *user)
{
	struct client *client;
	buffer_t *input_buf;
	const char *input_base64;

	input_base64 = getenv("CLIENT_INPUT");
	input_buf = input_base64 == NULL ? NULL :
		t_base64_decode_str(input_base64);

	client = client_create(STDIN_FILENO, STDOUT_FILENO, user, set);
	client_add_input(client, input_buf);
}

static void main_stdio_run(void)
{
	struct mail_storage_service_input input;
	struct mail_user *mail_user;
	const struct imap_settings *set;
	const char *value;

	memset(&input, 0, sizeof(input));
	input.module = input.service = "imap";
	input.username = getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL)
		i_fatal("USER environment missing");
	if ((value = getenv("IP")) != NULL)
		net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		net_addr2ip(value, &input.local_ip);

	user_initialized = TRUE;
	mail_user = mail_storage_service_init_user(master_service,
						   &input, set_roots,
						   storage_service_flags);
	set = mail_storage_service_get_settings(master_service);
	restrict_access_allow_coredumps(TRUE);
	if (set->shutdown_clients)
		master_service_set_die_with_master(master_service, TRUE);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);
	main_stdio_init_user(set, mail_user);
}

static void
login_client_connected(const struct master_login_client *client,
		       const char *username, const char *const *extra_fields)
{
	struct mail_storage_service_input input;
	struct mail_user *mail_user;
	struct client *imap_client;
	const struct imap_settings *set;
	buffer_t input_buf;

	if (imap_clients != NULL) {
		i_error("Can't handle more than one connection currently");
		(void)close(client->fd);
		return;
	}
	i_assert(!user_initialized);

	memset(&input, 0, sizeof(input));
	input.module = input.service = "imap";
	input.local_ip = client->auth_req.local_ip;
	input.remote_ip = client->auth_req.remote_ip;
	input.username = username;
	input.userdb_fields = extra_fields;

	if (input.username == NULL) {
		i_error("login client: Username missing from auth reply");
		(void)close(client->fd);
		return;
	}
	user_initialized = TRUE;
	master_login_deinit(&master_login);

	mail_user = mail_storage_service_init_user(master_service,
						   &input, set_roots,
						   storage_service_flags);
	set = mail_storage_service_get_settings(master_service);
	restrict_access_allow_coredumps(TRUE);
	if (set->shutdown_clients)
		master_service_set_die_with_master(master_service, TRUE);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	buffer_create_const_data(&input_buf, client->data,
				 client->auth_req.data_size);
	imap_client = client_create(client->fd, client->fd, mail_user, set);
	T_BEGIN {
		client_add_input(imap_client, &input_buf);
	} T_END;
}

static void client_connected(const struct master_service_connection *conn)
{
	if (master_login == NULL) {
		/* running standalone, we shouldn't even get here */
		(void)close(conn->fd);
	} else {
		master_login_add(master_login, conn->fd);
	}
}

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags = 0;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("* BAD [ALERT] imap binary must not be started from "
		       "inetd, use imap-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;
	}

	master_service = master_service_init("imap", service_flags,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		exit(FATAL_DEFAULT);
	master_service_init_finish(master_service);

	/* plugins may want to add commands, so this needs to be called early */
	commands_init();
	imap_fetch_handlers_init();

	if (IS_STANDALONE()) {
		T_BEGIN {
			main_stdio_run();
		} T_END;
	} else {
		master_login = master_login_init("auth-master",
						 login_client_connected);
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);
	clients_destroy_all();

	if (master_login != NULL)
		master_login_deinit(&master_login);
	if (user_initialized)
		mail_storage_service_deinit_user();
	imap_fetch_handlers_deinit();
	commands_deinit();

	master_service_deinit(&master_service);
	return 0;
}
