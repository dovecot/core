/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "ioloop.h"
#include "buffer.h"
#include "istream.h"
#include "istream-concat.h"
#include "ostream.h"
#include "path-util.h"
#include "base64.h"
#include "str.h"
#include "process-title.h"
#include "restrict-access.h"
#include "settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "login-server.h"
#include "master-interface.h"
#include "master-admin-client.h"
#include "mail-error.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-service.h"

#include <stdio.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

struct event_category event_category_pop3 = {
	.name = "pop3",
};

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;
static struct login_server *login_server = NULL;

pop3_client_created_func_t *hook_client_created = NULL;

pop3_client_created_func_t *
pop3_client_created_hook_set(pop3_client_created_func_t *new_hook)
{
	pop3_client_created_func_t *old_hook = hook_client_created;

	hook_client_created = new_hook;
	return old_hook;
}

void pop3_refresh_proctitle(void)
{
	struct client *client;
	string_t *title = t_str_new(128);

	if (!verbose_proctitle)
		return;

	str_append_c(title, '[');
	switch (pop3_client_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = pop3_clients;
		str_append(title, client->user->username);
		if (client->user->conn.remote_ip != NULL) {
			str_append_c(title, ' ');
			str_append(title,
				   net_ip2addr(client->user->conn.remote_ip));
		}
		if (client->destroyed)
			str_append(title, " (deinit)");
		break;
	default:
		str_printfa(title, "%u connections", pop3_client_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void pop3_die(void)
{
	/* do nothing. pop3 connections typically die pretty quick anyway. */
}

static void client_add_input(struct client *client, const buffer_t *buf)
{
	struct ostream *output;

	if (buf != NULL && buf->used > 0) {
		struct istream *inputs[] = {
			i_stream_create_copy_from_data(buf->data, buf->used),
			client->input,
			NULL
		};
		client->input = i_stream_create_concat(inputs);
		i_stream_copy_fd(client->input, inputs[1]);
		i_stream_unref(&inputs[0]);
		i_stream_unref(&inputs[1]);
		i_stream_set_input_pending(client->input, TRUE);
	}

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	(void)client_handle_input(client);
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static int
client_create_from_input(const struct mail_storage_service_input *input,
			 int fd_in, int fd_out, struct client **client_r,
			 const char **error_r)
{
	const char *lookup_error_str =
		"-ERR [SYS/TEMP] "MAIL_ERRSTR_CRITICAL_MSG"\r\n";
	struct mail_user *mail_user;
	struct pop3_settings *set;

	struct event *event = event_create(NULL);
	event_add_category(event, &event_category_pop3);
	event_add_fields(event, (const struct event_add_field []){
		{ .key = "user", .value = input->username },
		{ .key = NULL }
	});
	if (input->local_ip.family != 0)
		event_add_ip(event, "local_ip", &input->local_ip);
	if (input->local_port != 0)
		event_add_int(event, "local_port", input->local_port);
	if (input->remote_ip.family != 0)
		event_add_ip(event, "remote_ip", &input->remote_ip);
	if (input->remote_port != 0)
		event_add_int(event, "remote_port", input->remote_port);

	struct mail_storage_service_input service_input = *input;
	service_input.event_parent = event;

	if (mail_storage_service_lookup_next(storage_service, &service_input,
					     &mail_user, error_r) <= 0) {
		if (write(fd_out, lookup_error_str, strlen(lookup_error_str)) < 0) {
			/* ignored */
		}
		event_unref(&event);
		return -1;
	}
	restrict_access_allow_coredumps(TRUE);

	if (settings_get(mail_user->event, &pop3_setting_parser_info, 0,
			 &set, error_r) < 0) {
		if (write(fd_out, lookup_error_str, strlen(lookup_error_str)) < 0) {
			/* ignored */
		}
		mail_user_deinit(&mail_user);
		event_unref(&event);
		return -1;
	}
	if (set->verbose_proctitle)
		verbose_proctitle = TRUE;

	*client_r = client_create(fd_in, fd_out, event, mail_user, set);
	event_unref(&event);
	return 0;
}

static int lock_session(struct client *client)
{
	int ret;

	i_assert(client->user->namespaces != NULL);
	i_assert(client->set->pop3_lock_session);

	if ((ret = pop3_lock_session(client)) <= 0) {
		client_send_line(client, ret < 0 ?
			"-ERR [SYS/TEMP] Failed to create POP3 session lock." :
			"-ERR [IN-USE] Mailbox is locked by another POP3 session.");
		client_destroy(client, "Couldn't lock POP3 session");
		return -1;
	}

	return 0;
}

#define MSG_BYE_INTERNAL_ERROR "-ERR "MAIL_ERRSTR_CRITICAL_MSG
static int init_namespaces(struct client *client, bool already_logged_in)
{
	const char *error;
	int ret;

	/* finish initializing the user (see comment in main()) */
	ret = mail_namespaces_init(client->user, &error);
	if (ret == 0) {
		i_assert(client->inbox_ns == NULL);
		client->inbox_ns = mail_namespace_find_inbox(client->user->namespaces);
		i_assert(client->inbox_ns != NULL);

		client->mail_set = mailbox_list_get_mail_set(client->inbox_ns->list);
		pool_ref(client->mail_set->pool);
	}

	if (ret < 0) {
		if (!already_logged_in)
			client_send_line(client, MSG_BYE_INTERNAL_ERROR);

		e_error(client->event, "%s", error);
		client_destroy(client, error);
		return -1;
	}
	return 0;
}

static void client_init_session(struct client *client)
{
	const char *error;

	/*
	 * RFC 1939 requires that the session lock gets acquired before the
	 * positive response is sent to the client indicating a transition
	 * to the TRANSACTION state.
	 *
	 * Since the session lock is stored under the INBOX's storage
	 * directory, the locking code requires that the namespaces are
	 * initialized first.
	 *
	 * If the system administrator configured dovecot to not use session
	 * locks, we can send back the positive response before the
	 * potentially long-running namespace initialization occurs.  This
	 * avoids the client possibly timing out during authentication due
	 * to storage initialization taking too long.
	 */
	if (client->set->pop3_lock_session) {
		if (init_namespaces(client, FALSE) < 0)
			return; /* no need to propagate an error */

		if (lock_session(client) < 0)
			return; /* no need to propagate an error */

		if (!IS_STANDALONE())
			client_send_line(client, "+OK Logged in.");
	} else {
		if (!IS_STANDALONE())
			client_send_line(client, "+OK Logged in.");

		if (init_namespaces(client, TRUE) < 0)
			return; /* no need to propagate an error */
	}

	struct event_reason *reason = event_reason_begin("pop3:initialize");
	int ret = client_init_mailbox(client, &error);
	event_reason_end(&reason);

	if (ret < 0) {
		e_error(client->event, "%s", error);
		client_destroy(client, error);
	}
}

static void main_stdio_run(const char *username)
{
	struct client *client;
	struct mail_storage_service_input input;
	buffer_t *input_buf;
	const char *value, *error, *input_base64;

	i_zero(&input);
	input.service = "pop3";
	input.username = username != NULL ? username : getenv("USER");
	if (input.username == NULL && IS_STANDALONE())
		input.username = getlogin();
	if (input.username == NULL)
		i_fatal("USER environment missing");
	if ((value = getenv("IP")) != NULL)
		(void)net_addr2ip(value, &input.remote_ip);
	if ((value = getenv("LOCAL_IP")) != NULL)
		(void)net_addr2ip(value, &input.local_ip);

	input_base64 = getenv("CLIENT_INPUT");
	input_buf = input_base64 == NULL ? NULL :
		t_base64_decode_str(input_base64);

	if (client_create_from_input(&input, STDIN_FILENO, STDOUT_FILENO,
				     &client, &error) < 0)
		i_fatal("%s", error);
	client_add_input(client, input_buf);
	client_create_finish(client);

	client_init_session(client);
	/* client may be destroyed now */
}

static void
login_request_finished(const struct login_server_request *login_client,
		       const char *username, const char *const *extra_fields)
{
	struct client *client;
	struct mail_storage_service_input input;
	enum login_request_flags flags = login_client->auth_req.flags;
	const char *error;
	buffer_t input_buf;

	i_zero(&input);
	input.service = "pop3";
	input.local_ip = login_client->auth_req.local_ip;
	input.remote_ip = login_client->auth_req.remote_ip;
	input.local_port = login_client->auth_req.local_port;
	input.remote_port = login_client->auth_req.remote_port;
	input.username = username;
	input.userdb_fields = extra_fields;
	input.session_id = login_client->session_id;
	if ((flags & LOGIN_REQUEST_FLAG_END_CLIENT_SECURED_TLS) != 0)
		input.end_client_tls_secured = TRUE;

	buffer_create_from_const_data(&input_buf, login_client->data,
				      login_client->auth_req.data_size);
	if (client_create_from_input(&input, login_client->fd, login_client->fd,
				     &client, &error) < 0) {
		int fd = login_client->fd;

		i_error("%s", error);
		i_close_fd(&fd);
		master_service_client_connection_destroyed(master_service);
		return;
	}
	client_add_input(client, &input_buf);
	client_create_finish(client);

	client_init_session(client);
	/* client may be destroyed now */
}

static void login_request_failed(const struct login_server_request *request,
				const char *errormsg)
{
	const char *msg;

	msg = t_strdup_printf("-ERR [SYS/TEMP] %s\r\n", errormsg);
	if (write(request->fd, msg, strlen(msg)) < 0) {
		/* ignored */
	}
}

static unsigned int
master_admin_cmd_kick_user(const char *user, const guid_128_t conn_guid)
{
	struct client *client, *next;
	unsigned int count = 0;

	for (client = pop3_clients; client != NULL; client = next) {
		next = client->next;
		if (strcmp(client->user->username, user) == 0 &&
		    (guid_128_is_empty(conn_guid) ||
		     guid_128_cmp(client->anvil_conn_guid, conn_guid) == 0))
			client_kick(client, FALSE);
	}
	return count;
}

static const struct master_admin_client_callback admin_callbacks = {
	.cmd_kick_user = master_admin_cmd_kick_user,
};

static void client_connected(struct master_service_connection *conn)
{
	/* when running standalone, we shouldn't even get here */
	i_assert(login_server != NULL);

	master_service_client_connection_accept(conn);
	login_server_add(login_server, conn->fd);
}

int main(int argc, char *argv[])
{
	struct login_server_settings login_set;
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags = 0;
	const char *username = NULL;
	const char *error;
	int c;

	i_zero(&login_set);
	login_set.postlogin_timeout_secs =
		LOGIN_SERVER_POSTLOGIN_TIMEOUT_DEFAULT;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("-ERR [SYS/PERM] pop3 binary must not be started from "
		       "inetd, use pop3-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	}

	/*
	 * We include MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES so that the
	 * mail_user initialization is fast and we can quickly send back the
	 * OK response to LOGIN/AUTHENTICATE.  Otherwise we risk a very slow
	 * namespace initialization to cause client timeouts on login.
	 */
	storage_service_flags |= MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES;

	master_service = master_service_init("pop3", service_flags,
					     &argc, &argv, "t:u:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
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
		default:
			return FATAL_DEFAULT;
		}
	}

	if (master_service_settings_read_simple(master_service, &error) < 0)
		i_fatal("%s", error);

	const struct master_service_settings *master_set =
		master_service_get_service_settings(master_service);
	if (t_abspath(master_set->auth_master_socket_path,
		      &login_set.auth_socket_path, &error) < 0) {
		i_fatal("t_abspath(%s) failed: %s",
			master_set->auth_master_socket_path, error);
	}

	if (argv[optind] != NULL) {
		if (t_abspath(argv[optind], &login_set.postlogin_socket_path, &error) < 0) {
			i_fatal("t_abspath(%s) failed: %s", argv[optind], error);
		}
	}
	login_set.callback = login_request_finished;
	login_set.failure_callback = login_request_failed;
	login_set.update_proctitle =
		getenv(MASTER_VERBOSE_PROCTITLE_ENV) != NULL &&
		master_service_get_client_limit(master_service) == 1;
	if (!IS_STANDALONE())
		login_server = login_server_init(master_service, &login_set);

	master_admin_clients_init(&admin_callbacks);
	master_service_set_die_callback(master_service, pop3_die);

	storage_service =
		mail_storage_service_init(master_service,
					  storage_service_flags);
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

	if (login_server != NULL)
		login_server_deinit(&login_server);
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
