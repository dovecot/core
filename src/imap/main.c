/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "abspath.h"
#include "str.h"
#include "base64.h"
#include "process-title.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-login.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imap-fetch.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

#define IMAP_DIE_IDLE_SECS 10

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;
static struct master_login *master_login = NULL;

imap_client_created_func_t *hook_client_created = NULL;

imap_client_created_func_t *
imap_client_created_hook_set(imap_client_created_func_t *new_hook)
{
	imap_client_created_func_t *old_hook = hook_client_created;

	hook_client_created = new_hook;
	return old_hook;
}

void imap_refresh_proctitle(void)
{
#define IMAP_PROCTITLE_PREFERRED_LEN 80
	struct client *client;
	struct client_command_context *cmd;
	string_t *title = t_str_new(128);

	if (!verbose_proctitle)
		return;

	str_append_c(title, '[');
	switch (imap_client_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = imap_clients;
		str_append(title, client->user->username);
		if (client->user->remote_ip != NULL) {
			str_append_c(title, ' ');
			str_append(title, net_ip2addr(client->user->remote_ip));
		}
		for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
			if (cmd->name == NULL)
				continue;

			if (str_len(title) > IMAP_PROCTITLE_PREFERRED_LEN)
				break;
			str_append_c(title, ' ');
			str_append(title, cmd->name);
		}
		break;
	default:
		str_printfa(title, "%u connections", imap_client_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void client_kill_idle(struct client *client)
{
	if (client->output_lock != NULL)
		return;

	client_send_line(client, "* BYE Server shutting down.");
	client_destroy(client, "Server shutting down.");
}

static void imap_die(void)
{
	struct client *client, *next;
	time_t last_io, now = time(NULL);
	time_t stop_timestamp = now - IMAP_DIE_IDLE_SECS;
	unsigned int stop_msecs;

	for (client = imap_clients; client != NULL; client = next) {
		next = client->next;

		last_io = I_MAX(client->last_input, client->last_output);
		if (last_io <= stop_timestamp)
			client_kill_idle(client);
		else {
			timeout_remove(&client->to_idle);
			stop_msecs = (last_io - stop_timestamp) * 1000;
			client->to_idle = timeout_add(stop_msecs,
						      client_kill_idle, client);
		}
	}
}

struct client_input {
	const char *tag;

	const unsigned char *input;
	unsigned int input_size;
	bool send_untagged_capability;
};

static void
client_parse_input(const unsigned char *data, unsigned int len,
		   struct client_input *input_r)
{
	unsigned int taglen;

	i_assert(len > 0);

	memset(input_r, 0, sizeof(*input_r));

	if (data[0] == '1')
		input_r->send_untagged_capability = TRUE;
	data++; len--;

	input_r->tag = t_strndup(data, len);
	taglen = strlen(input_r->tag) + 1;

	if (len > taglen) {
		input_r->input = data + taglen;
		input_r->input_size = len - taglen;
	}
}

static void client_add_input(struct client *client, const buffer_t *buf)
{
	struct ostream *output;
	struct client_input input;

	if (buf != NULL && buf->used > 0) {
		client_parse_input(buf->data, buf->used, &input);
		if (input.input_size > 0 &&
		    !i_stream_add_data(client->input, input.input,
				       input.input_size))
			i_panic("Couldn't add client input to stream");
	} else {
		/* IMAPLOGINTAG environment is compatible with mailfront */
		memset(&input, 0, sizeof(input));
		input.tag = getenv("IMAPLOGINTAG");
	}

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	if (input.tag == NULL) {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY ",
			str_c(client->capability_string), "] "
			"Logged in as ", client->user->username, NULL));
	} else if (input.send_untagged_capability) {
		/* client doesn't seem to understand tagged capabilities. send
		   untagged instead and hope that it works. */
		client_send_line(client, t_strconcat("* CAPABILITY ",
			str_c(client->capability_string), NULL));
		client_send_line(client,
				 t_strconcat(input.tag, " OK Logged in", NULL));
	} else {
		client_send_line(client, t_strconcat(
			input.tag, " OK [CAPABILITY ",
			str_c(client->capability_string), "] Logged in", NULL));
	}
	(void)client_handle_input(client);
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static int
client_create_from_input(const struct mail_storage_service_input *input,
			 const struct master_login_client *login_client,
			 int fd_in, int fd_out, const buffer_t *input_buf,
			 const char **error_r)
{
	struct mail_storage_service_user *user;
	struct mail_user *mail_user;
	struct client *client;
	const struct imap_settings *set;
	enum mail_auth_request_flags flags;

	if (mail_storage_service_lookup_next(storage_service, input,
					     &user, &mail_user, error_r) <= 0)
		return -1;
	restrict_access_allow_coredumps(TRUE);

	set = mail_storage_service_user_get_set(user)[1];
	if (set->verbose_proctitle)
		verbose_proctitle = TRUE;

	client = client_create(fd_in, fd_out, mail_user, user, set);
	T_BEGIN {
		client_add_input(client, input_buf);
	} T_END;

	flags = login_client == NULL ? 0 : login_client->auth_req.flags;
	if ((flags & MAIL_AUTH_REQUEST_FLAG_TLS_COMPRESSION) != 0)
		client->tls_compression = TRUE;
	return 0;
}

static void main_stdio_run(const char *username)
{
	struct mail_storage_service_input input;
	const char *value, *error, *input_base64;
	buffer_t *input_buf;

	memset(&input, 0, sizeof(input));
	input.module = input.service = "imap";
	input.username = username != NULL ? username : getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL)
		i_fatal("USER environment missing");
	if ((value = getenv("IP")) != NULL)
		net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		net_addr2ip(value, &input.local_ip);

	input_base64 = getenv("CLIENT_INPUT");
	input_buf = input_base64 == NULL ? NULL :
		t_base64_decode_str(input_base64);

	if (client_create_from_input(&input, NULL, STDIN_FILENO, STDOUT_FILENO,
				     input_buf, &error) < 0)
		i_fatal("%s", error);
}

static void
login_client_connected(const struct master_login_client *client,
		       const char *username, const char *const *extra_fields)
{
#define MSG_BYE_INTERNAL_ERROR "* BYE "MAIL_ERRSTR_CRITICAL_MSG"\r\n"
	struct mail_storage_service_input input;
	const char *error;
	buffer_t input_buf;

	memset(&input, 0, sizeof(input));
	input.module = input.service = "imap";
	input.local_ip = client->auth_req.local_ip;
	input.remote_ip = client->auth_req.remote_ip;
	input.username = username;
	input.userdb_fields = extra_fields;

	buffer_create_const_data(&input_buf, client->data,
				 client->auth_req.data_size);
	if (client_create_from_input(&input, client, client->fd, client->fd,
				     &input_buf, &error) < 0) {
		if (write(client->fd, MSG_BYE_INTERNAL_ERROR,
			  strlen(MSG_BYE_INTERNAL_ERROR)) < 0) {
			if (errno != EAGAIN && errno != EPIPE)
				i_error("write(client) failed: %m");
		}
		i_error("%s", error);
		(void)close(client->fd);
		master_service_client_connection_destroyed(master_service);
	}
}

static void login_client_failed(const struct master_login_client *client,
				const char *errormsg)
{
	struct client_input input;
	const char *msg;

	client_parse_input(client->data, client->auth_req.data_size, &input);
	msg = t_strdup_printf("%s NO ["IMAP_RESP_CODE_UNAVAILABLE"] %s\r\n",
			      input.tag, errormsg);
	if (write(client->fd, msg, strlen(msg)) < 0) {
		/* ignored */
	}
}

static void client_connected(struct master_service_connection *conn)
{
	/* when running standalone, we shouldn't even get here */
	i_assert(master_login != NULL);

	master_service_client_connection_accept(conn);
	master_login_add(master_login, conn->fd);
}

int main(int argc, char *argv[])
{
	static const struct setting_parser_info *set_roots[] = {
		&imap_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags = 0;
	const char *postlogin_socket_path, *username = NULL;
	int c;

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
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;
	}

	master_service = master_service_init("imap", service_flags,
					     &argc, &argv, "u:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'u':
			storage_service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			username = optarg;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	postlogin_socket_path = argv[optind] == NULL ? NULL :
		t_abspath(argv[optind]);

	master_service_init_finish(master_service);
	master_service_set_die_callback(master_service, imap_die);

	/* plugins may want to add commands, so this needs to be called early */
	commands_init();
	imap_fetch_handlers_init();

	storage_service =
		mail_storage_service_init(master_service,
					  set_roots, storage_service_flags);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	if (IS_STANDALONE()) {
		T_BEGIN {
			main_stdio_run(username);
		} T_END;
	} else {
		master_login = master_login_init(master_service,
						 t_abspath("auth-master"),
						 postlogin_socket_path,
						 login_client_connected,
						 login_client_failed);
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);
	clients_destroy_all();

	if (master_login != NULL)
		master_login_deinit(&master_login);
	mail_storage_service_deinit(&storage_service);

	imap_fetch_handlers_deinit();
	commands_deinit();

	master_service_deinit(&master_service);
	return 0;
}
