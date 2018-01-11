/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

/*
The imap-urlauth service provides URLAUTH access between different accounts. If
user A has an URLAUTH that references a mail from user B, it makes a connection
to the imap-urlauth service to access user B's mail store to retrieve the
mail.

The authentication and authorization of the URLAUTH is performed within
this service. Because access to the mailbox and the associated mailbox keys is
necessary to retrieve the message and for verification of the URLAUTH, the
urlauth services need root privileges. To mitigate security concerns, the
retrieval and verification of the URLs is performed in a worker service that
drops root privileges and acts as target user B.

The imap-urlauth service thus consists of three separate stages:

- imap-urlauth-login:
  This is the login service which operates identical to imap-login and
  pop3-login equivalents, except for the fact that only token authentication is
  allowed. It verifies that the connecting client is an IMAP service acting on
  behaf of an authenticated user.

- imap-urlauth:
  Once the client is authenticated, the connection gets passed to the
  imap-urlauth service (as implemented here). The goal of this stage is 
  to prevent the need for re-authenticating to the imap-urlauth service when
  the clients wants to switch to a different target user. It normally runs as
  $default_internal_user and starts workers to perform the actual work. To start
  a worker, the imap-urlauth service establishes a control connection to the
  imap-urlauth-worker service. In the handshake phase of the control protocol,
  the connection of the client is passed to the worker. Once the worker
  finishes, a new worker is started and the client connection is transfered to
  it, unless the client is disconnected.

- imap-urlauth-worker:
  The worker handles the URLAUTH requests from the client, so this is where the
  mail store of the target user is accessed. The worker starts as root. In the
  protocol interaction the client first indicates what the target user is.
  The worker then performs a userdb lookup and drops privileges. The client can
  then submit URLAUTH requests, which are limited to that user. Once the client
  wants to access a different user, the worker terminates and the imap-urlauth
  service starts a new worker for the next target user.
*/

#include "imap-urlauth-common.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "buffer.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "path-util.h"
#include "base64.h"
#include "str.h"
#include "process-title.h"
#include "auth-master.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-login.h"
#include "master-interface.h"
#include "var-expand.h"

#include <stdio.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

bool verbose_proctitle = FALSE;
static struct master_login *master_login = NULL;

static const struct imap_urlauth_settings *imap_urlauth_settings;

void imap_urlauth_refresh_proctitle(void)
{
	struct client *client;
	string_t *title = t_str_new(128);

	if (!verbose_proctitle)
		return;

	str_append_c(title, '[');
	switch (imap_urlauth_client_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = imap_urlauth_clients;
		str_append(title, client->username);
		break;
	default:
		str_printfa(title, "%u connections", imap_urlauth_client_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void imap_urlauth_die(void)
{
	/* do nothing. imap_urlauth connections typically die pretty quick anyway. */
}

static int
client_create_from_input(const char *service, const char *username,
		int fd_in, int fd_out)
{
	struct client *client;

	if (client_create(service, username, fd_in, fd_out,
			  imap_urlauth_settings, &client) < 0)
		return -1;

	if (!IS_STANDALONE())
		client_send_line(client, "OK");
	return 0;
}

static void main_stdio_run(const char *username)
{
	username = username != NULL ? username : getenv("USER");
	if (username == NULL && IS_STANDALONE())
		username = getlogin();
	if (username == NULL)
		i_fatal("USER environment missing");

	(void)client_create_from_input("", username, STDIN_FILENO, STDOUT_FILENO);
}

static void
login_client_connected(const struct master_login_client *client,
		       const char *username, const char *const *extra_fields)
{
	const char *msg = "NO\n";
	struct auth_user_reply reply;
	struct net_unix_cred cred;
	const char *const *fields;
	const char *service = NULL;
	unsigned int count, i;

	auth_user_fields_parse(extra_fields, pool_datastack_create(), &reply);

	/* check peer credentials if possible */
	if (reply.uid != (uid_t)-1 && net_getunixcred(client->fd, &cred) == 0 &&
		reply.uid != cred.uid) {
		i_error("Peer's credentials (uid=%ld) do not match "
			"the user that logged in (uid=%ld).",
			(long)cred.uid, (long)reply.uid);
		if (write(client->fd, msg, strlen(msg)) < 0) {
			/* ignored */
		}
		net_disconnect(client->fd);
		return;
	}

	fields = array_get(&reply.extra_fields, &count);
	for (i = 0; i < count; i++) {
		if (str_begins(fields[i], "client_service=")) {
			service = fields[i] + 15;
			break;
		}
	}

	if (service == NULL) {
		i_error("Auth did not yield required client_service field (BUG).");
		if (write(client->fd, msg, strlen(msg)) < 0) {
			/* ignored */
		}
		net_disconnect(client->fd);
		return;
	}

	if (reply.anonymous)
		username = NULL;

	if (client_create_from_input(service, username, client->fd, client->fd) < 0)
		net_disconnect(client->fd);
}

static void login_client_failed(const struct master_login_client *client,
				const char *errormsg ATTR_UNUSED)
{
	const char *msg = "NO\n";
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
		&imap_urlauth_setting_parser_info,
		NULL
	};
	struct master_login_settings login_set;
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	void **sets;
	enum master_service_flags service_flags = 0;
	const char *error = NULL, *username = NULL;
	const char *auth_socket_path = "auth-master";
	int c;

	i_zero(&login_set);
	login_set.postlogin_timeout_secs = MASTER_POSTLOGIN_TIMEOUT_DEFAULT;

	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("NO imap_urlauth binary must not be started from "
		       "inetd, use imap-urlauth-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	}

	master_service = master_service_init("imap-urlauth", service_flags,
					     &argc, &argv, "a:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	master_service_init_log(master_service, "imap-urlauth: ");

	i_zero(&input);
	input.roots = set_roots;
	input.module = "imap-urlauth";
	input.service = "imap-urlauth";
	if (master_service_settings_read(master_service, &input, &output,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	sets = master_service_settings_get_others(master_service);
	imap_urlauth_settings = sets[0];	

	if (imap_urlauth_settings->verbose_proctitle)
		verbose_proctitle = TRUE;

	if (t_abspath(auth_socket_path, &login_set.auth_socket_path, &error) < 0) {
		i_fatal("t_abspath(%s) failed: %s", auth_socket_path, error);
	}
	login_set.callback = login_client_connected;
	login_set.failure_callback = login_client_failed;

	master_service_init_finish(master_service);
	master_service_set_die_callback(master_service, imap_urlauth_die);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	if (IS_STANDALONE()) {
		T_BEGIN {
			main_stdio_run(username);
		} T_END;
	} else {
		master_login = master_login_init(master_service, &login_set);
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);
	clients_destroy_all();

	if (master_login != NULL)
		master_login_deinit(&master_login);
	master_service_deinit(&master_service);
	return 0;
}
