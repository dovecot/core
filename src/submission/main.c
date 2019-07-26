/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "base64.h"
#include "hostpid.h"
#include "path-util.h"
#include "process-title.h"
#include "restrict-access.h"
#include "fd-util.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-login.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "var-expand.h"
#include "mail-error.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "smtp-server.h"
#include "smtp-client.h"

#include "submission-commands.h"

#include <stdio.h>
#include <unistd.h>

#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

struct smtp_server *smtp_server = NULL;
struct smtp_client *smtp_client = NULL;

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;
static struct master_login *master_login = NULL;

submission_client_created_func_t *hook_client_created = NULL;
bool submission_debug = FALSE;

submission_client_created_func_t *
submission_client_created_hook_set(submission_client_created_func_t *new_hook)
{
	submission_client_created_func_t *old_hook = hook_client_created;

	hook_client_created = new_hook;
	return old_hook;
}

void submission_refresh_proctitle(void)
{
	struct client *client;
	string_t *title = t_str_new(128);

	if (!verbose_proctitle)
		return;

	str_append_c(title, '[');
	switch (submission_client_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = submission_clients;
		str_append(title, client->user->username);
		if (client->user->conn.remote_ip != NULL) {
			str_append_c(title, ' ');
			str_append(title,
				   net_ip2addr(client->user->conn.remote_ip));
		}
		str_append_c(title, ' ');
		str_append(title, client_state_get_name(client));
		break;
	default:
		str_printfa(title, "%u connections", submission_client_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void submission_die(void)
{
	/* do nothing. submission connections typically die pretty quick anyway.
	 */
}

static void
send_error(int fd_out, const char *hostname, const char *error_code,
	   const char *error_msg)
{
	const char *msg;

	msg = t_strdup_printf("451 %s %s\r\n"
		"421 4.3.2 %s Shutting down due to fatal error\r\n",
		error_code, error_msg, hostname);
	if (write(fd_out, msg, strlen(msg)) < 0) {
		if (errno != EAGAIN && errno != EPIPE)
			i_error("write(client) failed: %m");
	}
}

static int
client_create_from_input(const struct mail_storage_service_input *input,
			 int fd_in, int fd_out, const buffer_t *input_buf,
			 const char **error_r)
{
	struct mail_storage_service_user *user;
	struct mail_user *mail_user;
	struct submission_settings *set;
	const char *errstr;
	const char *helo = NULL;
	const unsigned char *data;
	size_t data_len;

	if (mail_storage_service_lookup_next(storage_service, input,
					     &user, &mail_user, error_r) <= 0) {
		send_error(fd_out, my_hostname,
			"4.7.0", MAIL_ERRSTR_CRITICAL_MSG);
		return -1;
	}
	restrict_access_allow_coredumps(TRUE);

	set = mail_storage_service_user_get_set(user)[1];
	if (set->verbose_proctitle)
		verbose_proctitle = TRUE;

	if (settings_var_expand(&submission_setting_parser_info, set,
				mail_user->pool, mail_user_var_expand_table(mail_user),
				&errstr) <= 0) {
		*error_r = t_strdup_printf("Failed to expand settings: %s", errstr);
		send_error(fd_out, set->hostname,
			"4.3.5", MAIL_ERRSTR_CRITICAL_MSG);
		mail_user_deinit(&mail_user);
		mail_storage_service_user_unref(&user);
		return -1;
	}

	if (set->submission_relay_host == NULL ||
		*set->submission_relay_host == '\0') {
		*error_r = "No relay host configured for submission proxy "
			"(submission_relay_host is unset)";
		send_error(fd_out, set->hostname,
			"4.3.5", MAIL_ERRSTR_CRITICAL_MSG);
		mail_user_deinit(&mail_user);
		mail_storage_service_user_unref(&user);
		return -1;
	}

	/* parse input data */
	data = NULL;
	data_len = 0;
	if (input_buf != NULL && input_buf->used > 0) {
		size_t len = input_buf->used, helo_len = 0;

		data = input_buf->data;

		if (len > 0) {
			if (*data == '\0') {
				helo_len = 1;
			} else {
				helo = t_strndup(data, len);
				helo_len = strlen(helo) + 1;
			}
		}

		/* NOTE: actually, pipelining the AUTH command is stricly
		         speaking not allowed, but we support it anyway.
		 */
		if (len > helo_len) {
			data = data + helo_len;
			data_len = len - helo_len;
		}
	}

	(void)client_create(fd_in, fd_out, mail_user,
			    user, set, helo, data, data_len);
	return 0;
}

static void main_stdio_run(const char *username)
{
	struct mail_storage_service_input input;
	buffer_t *input_buf;
	const char *value, *error, *input_base64;

	i_zero(&input);
	input.module = input.service = "submission";
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
				     input_buf, &error) < 0)
		i_fatal("%s", error);
}

static void
login_client_connected(const struct master_login_client *login_client,
		       const char *username, const char *const *extra_fields)
{
	struct mail_storage_service_input input;
	enum mail_auth_request_flags flags = login_client->auth_req.flags;
	const char *error;
	buffer_t input_buf;

	i_zero(&input);
	input.module = input.service = "submission";
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

	buffer_create_from_const_data(&input_buf, login_client->data,
				      login_client->auth_req.data_size);
	if (client_create_from_input(&input, login_client->fd, login_client->fd,
				     &input_buf, &error) < 0) {
		int fd = login_client->fd;
		i_error("%s", error);
		i_close_fd(&fd);
		master_service_client_connection_destroyed(master_service);
	}
}

static void login_client_failed(const struct master_login_client *client,
				const char *errormsg)
{
	const char *msg;

	msg = t_strdup_printf("451 4.7.0 %s\r\n"
		"421 4.3.2 %s Shutting down due to fatal error\r\n",
		errormsg, my_hostname);
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
		&submission_setting_parser_info,
		NULL
	};
	struct master_login_settings login_set;
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags = 0;
	struct smtp_server_settings smtp_server_set;
	struct smtp_client_settings smtp_client_set;
	const char *username = NULL, *auth_socket_path = "auth-master";
	const char *error;
	int c;

	i_zero(&login_set);
	login_set.postlogin_timeout_secs = MASTER_POSTLOGIN_TIMEOUT_DEFAULT;
	login_set.request_auth_token = TRUE;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("421 5.3.5 The submission binary must not be started "
		       "from inetd, use submission-login instead.\r\n");
		return 1;
	}

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	}

	master_service = master_service_init("submission", service_flags,
					     &argc, &argv, "a:Dt:u:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		case 't':
			if (str_to_uint(optarg,
					&login_set.postlogin_timeout_secs) < 0 ||
			    login_set.postlogin_timeout_secs == 0)
				i_fatal("Invalid -t parameter: %s", optarg);
			break;
		case 'u':
			storage_service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			username = optarg;
			break;
		case 'D':
			submission_debug = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	if (t_abspath(auth_socket_path, &login_set.auth_socket_path,
		      &error) < 0) {
		i_fatal("t_abspath(%s) failed: %s", auth_socket_path,
			error);
	}
	if (argv[optind] != NULL) {
		if (t_abspath(argv[optind],
			      &login_set.postlogin_socket_path, &error) < 0) {
			i_fatal("t_abspath(%s) failed: %s",
				argv[optind], error);
		}
	}
	login_set.callback = login_client_connected;
	login_set.failure_callback = login_client_failed;

	master_service_set_die_callback(master_service, submission_die);

	storage_service =
		mail_storage_service_init(master_service,
					  set_roots, storage_service_flags);

	/* initialize SMTP server */
	i_zero(&smtp_server_set);
	smtp_server_set.capabilities = SMTP_CAPABILITY_DSN;
	smtp_server_set.protocol = SMTP_PROTOCOL_SMTP;
	smtp_server_set.max_pipelined_commands = 5;
	smtp_server_set.debug = submission_debug;
	smtp_server = smtp_server_init(&smtp_server_set);
	smtp_server_command_register(smtp_server, "BURL", cmd_burl, 0);

	/* initialize SMTP client */
	i_zero(&smtp_client_set);
	smtp_client_set.my_hostname = my_hostdomain();
	smtp_client_set.debug = submission_debug;
	smtp_client = smtp_client_init(&smtp_client_set);

	if (!IS_STANDALONE())
		master_login = master_login_init(master_service, &login_set);

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

	smtp_client_deinit(&smtp_client);
	smtp_server_deinit(&smtp_server);

	if (master_login != NULL)
		master_login_deinit(&master_login);
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
