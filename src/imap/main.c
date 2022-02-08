/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "path-util.h"
#include "str.h"
#include "base64.h"
#include "process-title.h"
#include "randgen.h"
#include "restrict-access.h"
#include "write-full.h"
#include "settings-parser.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-login.h"
#include "master-admin-client.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "smtp-submit-settings.h"
#include "imap-master-client.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imap-feature.h"
#include "imap-fetch.h"

#include <stdio.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

#define IMAP_DIE_IDLE_SECS 10

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;
static struct master_login *master_login = NULL;
static struct timeout *to_proctitle;

imap_client_created_func_t *hook_client_created = NULL;
bool imap_debug = FALSE;

struct event_category event_category_imap = {
	.name = "imap",
};

imap_client_created_func_t *
imap_client_created_hook_set(imap_client_created_func_t *new_hook)
{
	imap_client_created_func_t *old_hook = hook_client_created;

	hook_client_created = new_hook;
	return old_hook;
}

static void imap_refresh_proctitle_callback(void *context ATTR_UNUSED)
{
	timeout_remove(&to_proctitle);
	imap_refresh_proctitle();
}

void imap_refresh_proctitle_delayed(void)
{
	if (to_proctitle == NULL)
		to_proctitle = timeout_add_short(0,
			imap_refresh_proctitle_callback, NULL);
}

void imap_refresh_proctitle(void)
{
#define IMAP_PROCTITLE_PREFERRED_LEN 80
	struct client *client;
	struct client_command_context *cmd;
	string_t *title = t_str_new(128);
	bool wait_output;

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
		if (client->user->conn.remote_ip != NULL) {
			str_append_c(title, ' ');
			str_append(title,
				   net_ip2addr(client->user->conn.remote_ip));
		}
		wait_output = FALSE;
		for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
			if (cmd->name == NULL)
				continue;

			if (str_len(title) < IMAP_PROCTITLE_PREFERRED_LEN) {
				str_append_c(title, ' ');
				str_append(title, cmd->name);
			}
			if (cmd->state == CLIENT_COMMAND_STATE_WAIT_OUTPUT)
				wait_output = TRUE;
		}
		if (wait_output) {
			str_printfa(title, " - %zu bytes waiting",
				    o_stream_get_buffer_used_size(client->output));
			if (o_stream_is_corked(client->output))
				str_append(title, " corked");
		}
		if (client->destroyed)
			str_append(title, " (deinit)");
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
	if (client->output_cmd_lock != NULL)
		return;

	mail_storage_service_io_activate_user(client->service_user);
	client_send_line(client, "* BYE "MASTER_SERVICE_SHUTTING_DOWN_MSG".");
	client_destroy(client, MASTER_SERVICE_SHUTTING_DOWN_MSG);
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

struct imap_login_request {
	const char *tag;

	const unsigned char *input;
	size_t input_size;
	bool send_untagged_capability;
};

static void
client_parse_imap_login_request(const unsigned char *data, size_t len,
				struct imap_login_request *input_r)
{
	size_t taglen;

	i_zero(input_r);
	if (len == 0)
		return;

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

static void
client_send_login_reply(struct ostream *output, const char *capability_string,
			const char *preauth_username,
			const struct imap_login_request *request)
{
	string_t *reply = t_str_new(256);

	/* cork/uncork around the OK reply to minimize latency */
	o_stream_cork(output);
	if (request->tag == NULL) {
		str_printfa(reply, "* PREAUTH [CAPABILITY %s] Logged in as %s\r\n",
			    capability_string, preauth_username);
	} else if (capability_string == NULL) {
		/* Client initialization failed. There's no need to send
		   capabilities. Just send the tagged OK so the client knows
		   the login itself succeeded, followed by a BYE. */
		str_printfa(reply, "%s OK Logged in, but initialization failed.\r\n",
			    request->tag);
		str_append(reply, "* BYE "MAIL_ERRSTR_CRITICAL_MSG"\r\n");
	} else if (request->send_untagged_capability) {
		/* client doesn't seem to understand tagged capabilities. send
		   untagged instead and hope that it works. */
		str_printfa(reply, "* CAPABILITY %s\r\n", capability_string);
		str_printfa(reply, "%s OK Logged in\r\n", request->tag);
	} else {
		str_printfa(reply, "%s OK [CAPABILITY %s] Logged in\r\n",
			    request->tag, capability_string);
	}
	o_stream_nsend(output, str_data(reply), str_len(reply));
	if (o_stream_uncork_flush(output) < 0 &&
	    output->stream_errno != EPIPE)
		i_error("write(client) failed: %s", o_stream_get_error(output));
}

static void
client_add_input_finalize(struct client *client)
{
	struct ostream *output;

	/* try to condense any responses into as few packets as possible */
	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	(void)client_handle_input(client);
	o_stream_uncork(output);
	o_stream_unref(&output);

	/* we could have already handled LOGOUT, or we might need to continue
	   pending ambiguous commands. */
	client_continue_pending_input(client);
}

int client_create_from_input(const struct mail_storage_service_input *input,
			     int fd_in, int fd_out, bool unhibernated,
			     struct client **client_r, const char **error_r)
{
	struct mail_storage_service_input service_input;
	struct mail_storage_service_user *user;
	struct mail_user *mail_user;
	struct client *client;
	struct imap_settings *imap_set;
	struct smtp_submit_settings *smtp_set;
	struct event *event;
	const char *errstr;

	event = event_create(NULL);
	event_add_category(event, &event_category_imap);
	event_add_fields(event, (const struct event_add_field []){
		{ .key = "user", .value = input->username },
		{ .key = NULL }
	});
	if (input->local_ip.family != 0)
		event_add_str(event, "local_ip", net_ip2addr(&input->local_ip));
	if (input->local_port != 0)
		event_add_int(event, "local_port", input->local_port);
	if (input->remote_ip.family != 0)
		event_add_str(event, "remote_ip", net_ip2addr(&input->remote_ip));
	if (input->remote_port != 0)
		event_add_int(event, "remote_port", input->remote_port);

	service_input = *input;
	service_input.event_parent = event;
	if (mail_storage_service_lookup_next(storage_service, &service_input,
					     &user, &mail_user, error_r) <= 0) {
		event_unref(&event);
		return -1;
	}
	/* Add the session only after creating the user, because
	   input->session_id may be NULL */
	event_add_str(event, "session", mail_user->session_id);

	restrict_access_allow_coredumps(TRUE);

	smtp_set = mail_storage_service_user_get_set(user)[1];
	imap_set = mail_storage_service_user_get_set(user)[2];
	if (imap_set->verbose_proctitle)
		verbose_proctitle = TRUE;

	if (settings_var_expand(&smtp_submit_setting_parser_info, smtp_set,
				mail_user->pool, mail_user_var_expand_table(mail_user),
				&errstr) <= 0 ||
			settings_var_expand(&imap_setting_parser_info, imap_set,
				mail_user->pool, mail_user_var_expand_table(mail_user),
				&errstr) <= 0) {
		*error_r = t_strdup_printf("Failed to expand settings: %s", errstr);
		mail_user_deinit(&mail_user);
		mail_storage_service_user_unref(&user);
		event_unref(&event);
		return -1;
	}

	client = client_create(fd_in, fd_out, unhibernated,
			       event, mail_user, user, imap_set, smtp_set);
	client->userdb_fields = input->userdb_fields == NULL ? NULL :
		p_strarray_dup(client->pool, input->userdb_fields);
	event_unref(&event);
	*client_r = client;
	return 0;
}

static void main_stdio_run(const char *username)
{
	struct client *client;
	struct mail_storage_service_input input;
	struct imap_login_request request;
	const char *value, *error, *input_base64;

	i_zero(&input);
	input.module = input.service = "imap";
	input.username = username != NULL ? username : getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL)
		i_fatal("USER environment missing");
	if ((value = getenv("IP")) != NULL)
		(void)net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		(void)net_addr2ip(value, &input.local_ip);

	if (client_create_from_input(&input, STDIN_FILENO, STDOUT_FILENO,
				     FALSE, &client, &error) < 0)
		i_fatal("%s", error);

	input_base64 = getenv("CLIENT_INPUT");
	if (input_base64 == NULL) {
		/* IMAPLOGINTAG environment is compatible with mailfront */
		i_zero(&request);
		request.tag = getenv("IMAPLOGINTAG");
	} else {
		const buffer_t *input_buf = t_base64_decode_str(input_base64);
		client_parse_imap_login_request(input_buf->data, input_buf->used,
						&request);
		if (request.input_size > 0) {
			client_add_istream_prefix(client, request.input,
						  request.input_size);
		}
	}

	client_create_finish_io(client);
	client_send_login_reply(client->output,
				str_c(client->capability_string),
				client->user->username, &request);
	if (client_create_finish(client, &error) < 0)
		i_fatal("%s", error);
	client_add_input_finalize(client);
	/* client may be destroyed now */
}

static void
login_client_connected(const struct master_login_client *login_client,
		       const char *username, const char *const *extra_fields)
{
#define MSG_BYE_INTERNAL_ERROR "* BYE "MAIL_ERRSTR_CRITICAL_MSG"\r\n"
	struct mail_storage_service_input input;
	struct client *client;
	struct imap_login_request request;
	enum mail_auth_request_flags flags = login_client->auth_req.flags;
	const char *error;

	i_zero(&input);
	input.module = input.service = "imap";
	input.local_ip = login_client->auth_req.local_ip;
	input.remote_ip = login_client->auth_req.remote_ip;
	input.local_port = login_client->auth_req.local_port;
	input.remote_port = login_client->auth_req.remote_port;
	input.username = username;
	input.userdb_fields = extra_fields;
	input.session_id = login_client->session_id;
	if ((flags & MAIL_AUTH_REQUEST_FLAG_CONN_SECURED) != 0)
		input.conn_secured = TRUE;
	if ((flags & MAIL_AUTH_REQUEST_FLAG_CONN_SSL_SECURED) != 0)
		input.conn_ssl_secured = TRUE;

	client_parse_imap_login_request(login_client->data,
					login_client->auth_req.data_size,
					&request);

	if (client_create_from_input(&input, login_client->fd, login_client->fd,
				     FALSE, &client, &error) < 0) {
		int fd = login_client->fd;
		struct ostream *output =
			o_stream_create_fd_autoclose(&fd, IO_BLOCK_SIZE);
		client_send_login_reply(output, NULL, NULL, &request);
		o_stream_destroy(&output);

		i_error("%s", error);
		master_service_client_connection_destroyed(master_service);
		return;
	}
	if ((flags & MAIL_AUTH_REQUEST_FLAG_TLS_COMPRESSION) != 0)
		client->tls_compression = TRUE;
	if (request.input_size > 0) {
		client_add_istream_prefix(client, request.input,
					  request.input_size);
	}

	/* The order here is important:
	   1. Finish setting up rawlog, so all input/output is written there.
	   2. Send tagged reply to login before any potentially long-running
	      work (during which client could disconnect due to timeout).
	   3. Finish initializing user, which can potentially take a long time.
	*/
	client_create_finish_io(client);
	client_send_login_reply(client->output,
				str_c(client->capability_string),
				NULL, &request);
	if (client_create_finish(client, &error) < 0) {
		if (write_full(login_client->fd, MSG_BYE_INTERNAL_ERROR,
			       strlen(MSG_BYE_INTERNAL_ERROR)) < 0)
			if (errno != EAGAIN && errno != EPIPE)
				e_error(client->event,
					"write_full(client) failed: %m");

		e_error(client->event, "%s", error);
		client_destroy(client, error);
		return;
	}

	client_add_input_finalize(client);
	/* client may be destroyed now */
}

static void login_client_failed(const struct master_login_client *client,
				const char *errormsg)
{
	struct imap_login_request request;
	const char *msg;

	client_parse_imap_login_request(client->data,
					client->auth_req.data_size, &request);
	msg = t_strdup_printf("%s NO ["IMAP_RESP_CODE_UNAVAILABLE"] %s\r\n",
			      request.tag, errormsg);
	if (write(client->fd, msg, strlen(msg)) < 0) {
		/* ignored */
	}
}

static unsigned int
master_admin_cmd_kick_user(const char *user, const guid_128_t conn_guid)
{
	struct client *client, *next;
	unsigned int count = 0;

	for (client = imap_clients; client != NULL; client = next) {
		next = client->next;
		if (strcmp(client->user->username, user) == 0 &&
		    (guid_128_is_empty(conn_guid) ||
		     guid_128_cmp(client->anvil_conn_guid, conn_guid) == 0))
			client_kick(client);
	}
	return count;
}

static const struct master_admin_client_callback admin_callbacks = {
	.cmd_kick_user = master_admin_cmd_kick_user,
};

static void client_connected(struct master_service_connection *conn)
{
	/* when running standalone, we shouldn't even get here */
	i_assert(master_login != NULL);

	master_service_client_connection_accept(conn);
	if (strcmp(conn->name, "imap-master") == 0) {
		/* restoring existing IMAP connection (e.g. from imap-idle) */
		imap_master_client_create(conn->fd);
		return;
	}
	master_login_add(master_login, conn->fd);
}

int main(int argc, char *argv[])
{
	static const struct setting_parser_info *set_roots[] = {
		&smtp_submit_setting_parser_info,
		&imap_setting_parser_info,
		NULL
	};
	struct master_login_settings login_set;
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_NO_SSL_CA |
		/*
		 * We include MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES so
		 * that the mail_user initialization is fast and we can
		 * quickly send back the OK response to LOGIN/AUTHENTICATE.
		 * Otherwise we risk a very slow namespace initialization to
		 * cause client timeouts on login.
		 */
		MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES;
	const char *username = NULL, *auth_socket_path = "auth-master";
	int c;

	i_zero(&login_set);
	login_set.postlogin_timeout_secs = MASTER_POSTLOGIN_TIMEOUT_DEFAULT;
	login_set.request_auth_token = TRUE;

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
	}

	master_service = master_service_init("imap", service_flags,
					     &argc, &argv, "a:Dt:u:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		case 't':
			if (str_to_uint(optarg, &login_set.postlogin_timeout_secs) < 0 ||
			    login_set.postlogin_timeout_secs == 0)
				i_fatal("Invalid -t parameter: %s", optarg);
			break;
		case 'u':
			storage_service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			username = optarg;
			break;
		case 'D':
			imap_debug = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	master_admin_clients_init(&admin_callbacks);
	master_service_set_die_callback(master_service, imap_die);

	/* plugins may want to add commands, so this needs to be called early */
	commands_init();
	imap_fetch_handlers_init();
	imap_features_init();
	clients_init();
	imap_master_clients_init();

	const char *error;
	if (t_abspath(auth_socket_path, &login_set.auth_socket_path, &error) < 0)
		i_fatal("t_abspath(%s) failed: %s", auth_socket_path, error);

	if (argv[optind] != NULL) {
		if (t_abspath(argv[optind], &login_set.postlogin_socket_path, &error) < 0)
			i_fatal("t_abspath(%s) failed: %s", argv[optind], error);
	}
	login_set.callback = login_client_connected;
	login_set.failure_callback = login_client_failed;

	if (!IS_STANDALONE())
		master_login = master_login_init(master_service, &login_set);

	storage_service =
		mail_storage_service_init(master_service,
					  set_roots, storage_service_flags);
	master_service_init_finish(master_service);
	/* NOTE: login_set.*_socket_path are now invalid due to data stack
	   having been freed */

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	if (IS_STANDALONE()) {
		T_BEGIN {
			main_stdio_run(username);
		} T_END;
	} else {
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);
	clients_destroy_all();

	if (master_login != NULL)
		master_login_deinit(&master_login);
	mail_storage_service_deinit(&storage_service);

	imap_fetch_handlers_deinit();
	imap_features_deinit();

	commands_deinit();
	imap_master_clients_deinit();

	timeout_remove(&to_proctitle);
	master_service_deinit(&master_service);
	return 0;
}
