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
#include "login-server.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "master-admin-client.h"
#include "var-expand.h"
#include "mail-error.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "smtp-server.h"
#include "smtp-client.h"

#include "submission-commands.h"

#include <stdio.h>
#include <unistd.h>

#define DNS_CLIENT_SOCKET_PATH "dns-client"

#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

struct smtp_server *smtp_server = NULL;
struct smtp_client *smtp_client = NULL;

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;
static struct login_server *login_server = NULL;

submission_client_created_func_t *hook_client_created = NULL;
bool submission_debug = FALSE;

struct event_category event_category_submission = {
	.name = "submission",
};

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
		str_append(title, smtp_server_state_names[client->state.state]);
		if (client->state.args != NULL && *client->state.args != '\0') {
			str_append_c(title, ' ');
			str_append(title, client->state.args);
		}
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
send_error(int fd_out, struct event *event, const char *hostname,
	   const char *error_code, const char *error_msg)
{
	const char *msg;

	msg = t_strdup_printf("451 %s %s\r\n"
		"421 4.3.2 %s Shutting down due to fatal error\r\n",
		error_code, error_msg, hostname);
	if (write(fd_out, msg, strlen(msg)) < 0) {
		if (errno != EAGAIN && errno != EPIPE && errno != ECONNRESET)
			e_error(event, "write(client) failed: %m");
	}
}

static bool
extract_input_data_field(const unsigned char **data, size_t *data_len,
			 const char **value_r)
{
	size_t value_len = 0;

	if (*data_len == 0)
		return FALSE;

	if (**data == '\0') {
		value_len = 1;
	} else {
		*value_r = t_strndup(*data, *data_len);
		value_len = strlen(*value_r) + 1;
	}

	if (value_len > *data_len) {
		*data = &uchar_nul;
		*data_len = 0;
	} else {
		*data = *data + value_len;
		*data_len = *data_len - value_len;
	}
	return TRUE;
}

static int
client_create_from_input(const struct mail_storage_service_input *input,
			 enum login_request_flags login_flags,
			 int fd_in, int fd_out, const buffer_t *input_buf,
			 const char **error_r)
{
	struct mail_storage_service_input service_input;
	struct mail_user *mail_user;
	struct submission_settings *set;
	bool no_greeting = HAS_ALL_BITS(login_flags,
					LOGIN_REQUEST_FLAG_IMPLICIT);
	struct event *event;
	const char *helo = NULL;
	struct smtp_proxy_data proxy_data;
	const unsigned char *data;
	size_t data_len;

	event = event_create(NULL);
	event_add_category(event, &event_category_submission);
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

	service_input = *input;
	service_input.event_parent = event;
	if (mail_storage_service_lookup_next(storage_service, &service_input,
					     &mail_user, error_r) <= 0) {
		send_error(fd_out, event, my_hostname,
			"4.7.0", MAIL_ERRSTR_CRITICAL_MSG);
		event_unref(&event);
		return -1;
	}
	/* Add the session only after creating the user, because
	   input->session_id may be NULL */
	event_add_str(event, "session", mail_user->session_id);

	restrict_access_allow_coredumps(TRUE);

	set = settings_parser_get_root_set(mail_user->set_parser,
			&submission_setting_parser_info);
	if (set->verbose_proctitle)
		verbose_proctitle = TRUE;

	if (set->submission_relay_host == NULL ||
		*set->submission_relay_host == '\0') {
		*error_r = "No relay host configured for submission proxy "
			"(submission_relay_host is unset)";
		send_error(fd_out, event, set->hostname,
			   "4.3.5", MAIL_ERRSTR_CRITICAL_MSG);
		mail_user_deinit(&mail_user);
		event_unref(&event);
		return -1;
	}

	/* parse input data */
	data = NULL;
	data_len = 0;
	i_zero(&proxy_data);
	if (input_buf != NULL && input_buf->used > 0) {
		data = input_buf->data;
		data_len = input_buf->used;

		if (extract_input_data_field(&data, &data_len, &helo) &&
		    extract_input_data_field(&data, &data_len,
					     &proxy_data.helo)) {
			/* nothing to do */
		}

		/* NOTE: actually, pipelining the AUTH command is stricly
		         speaking not allowed, but we support it anyway.
		 */
	}

	(void)client_create(fd_in, fd_out, event, mail_user,
			    set, helo, &proxy_data, data, data_len,
			    no_greeting);
	event_unref(&event);
	return 0;
}

static void main_stdio_run(const char *username)
{
	struct mail_storage_service_input input;
	buffer_t *input_buf;
	const char *value, *error, *input_base64;

	i_zero(&input);
	input.service = "submission";
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

	if (client_create_from_input(&input, 0, STDIN_FILENO, STDOUT_FILENO,
				     input_buf, &error) < 0)
		i_fatal("%s", error);
}

static void
login_request_finished(const struct login_server_request *request,
		       const char *username, const char *const *extra_fields)
{
	struct mail_storage_service_input input;
	enum login_request_flags flags = request->auth_req.flags;
	const char *error;
	buffer_t input_buf;

	i_zero(&input);
	input.service = "submission";
	input.local_ip = request->auth_req.local_ip;
	input.remote_ip = request->auth_req.remote_ip;
	input.local_port = request->auth_req.local_port;
	input.remote_port = request->auth_req.remote_port;
	input.username = username;
	input.userdb_fields = extra_fields;
	input.session_id = request->session_id;
	if ((flags & LOGIN_REQUEST_FLAG_END_CLIENT_SECURED_TLS) != 0)
		input.end_client_tls_secured = TRUE;

	buffer_create_from_const_data(&input_buf, request->data,
				      request->auth_req.data_size);
	if (client_create_from_input(&input, flags, request->fd, request->fd,
				     &input_buf, &error) < 0) {
		int fd = request->fd;
		i_error("%s", error);
		i_close_fd(&fd);
		master_service_client_connection_destroyed(master_service);
	}
}

static void login_request_failed(const struct login_server_request *request,
				 const char *errormsg)
{
	const char *msg;

	msg = t_strdup_printf("451 4.7.0 %s\r\n"
		"421 4.3.2 %s Shutting down due to fatal error\r\n",
		errormsg, my_hostname);
	if (write(request->fd, msg, strlen(msg)) < 0) {
		/* ignored */
	}
}

static unsigned int
master_admin_cmd_kick_user(const char *user, const guid_128_t conn_guid)
{
	struct client *client, *next;
	unsigned int count = 0;

	for (client = submission_clients; client != NULL; client = next) {
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
	i_assert(login_server != NULL);

	master_service_client_connection_accept(conn);
	login_server_add(login_server, conn->fd);
}

int main(int argc, char *argv[])
{
	static const struct setting_parser_info *set_roots[] = {
		&submission_setting_parser_info,
		NULL
	};
	struct login_server_settings login_set;
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags = 0;
	struct smtp_server_settings smtp_server_set;
	struct smtp_client_settings smtp_client_set;
	const char *username = NULL, *auth_socket_path = "auth-master";
	const char *tmp_socket_path;
	const char *error;
	int c;

	i_zero(&login_set);
	login_set.postlogin_timeout_secs =
		LOGIN_SERVER_POSTLOGIN_TIMEOUT_DEFAULT;
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
	login_set.callback = login_request_finished;
	login_set.failure_callback = login_request_failed;
	login_set.update_proctitle =
		getenv(MASTER_VERBOSE_PROCTITLE_ENV) != NULL &&
		master_service_get_client_limit(master_service) == 1;

	master_admin_clients_init(&admin_callbacks);
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
	smtp_server_set.reason_code_module = "submission";
	smtp_server = smtp_server_init(&smtp_server_set);
	smtp_server_command_register(smtp_server, "BURL", cmd_burl, 0);

	if (t_abspath(DNS_CLIENT_SOCKET_PATH, &tmp_socket_path, &error) < 0)
		i_fatal("t_abspath(%s) failed: %s", DNS_CLIENT_SOCKET_PATH, error);

	/* initialize SMTP client */
	i_zero(&smtp_client_set);
	smtp_client_set.my_hostname = my_hostdomain();
	smtp_client_set.debug = submission_debug;
	smtp_client_set.dns_client_socket_path = tmp_socket_path;
	smtp_client = smtp_client_init(&smtp_client_set);

	if (!IS_STANDALONE())
		login_server = login_server_init(master_service, &login_set);

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

	if (login_server != NULL)
		login_server_deinit(&login_server);
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
