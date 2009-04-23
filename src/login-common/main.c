/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "randgen.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "process-title.h"
#include "master-auth.h"
#include "master-service.h"
#include "master-interface.h"
#include "client-common.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "login-proxy.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

struct auth_client *auth_client;
bool closing_down;

struct master_service *service;
struct login_settings *login_settings;

static bool ssl_connections = FALSE;

static void client_connected(const struct master_service_connection *conn)
{
	struct client *client;
	struct ssl_proxy *proxy;
	struct ip_addr local_ip;
	unsigned int local_port;
	int fd_ssl;

	if (net_getsockname(conn->fd, &local_ip, &local_port) < 0) {
		memset(&local_ip, 0, sizeof(local_ip));
		local_port = 0;
	}

	// FIXME: a global ssl_connections isn't enough!
	if (!ssl_connections) {
		client = client_create(conn->fd, FALSE, &local_ip,
				       &conn->remote_ip);
	} else {
		fd_ssl = ssl_proxy_new(conn->fd, &conn->remote_ip, &proxy);
		if (fd_ssl == -1) {
			net_disconnect(conn->fd);
			return;
		}

		client = client_create(fd_ssl, TRUE,
				       &local_ip, &conn->remote_ip);
		client->proxying = TRUE;
		client->proxy = proxy;
	}
	client->remote_port = conn->remote_port;
	client->local_port = local_port;
}

static void auth_connect_notify(struct auth_client *client ATTR_UNUSED,
				bool connected, void *context ATTR_UNUSED)
{
	if (connected)
                clients_notify_auth_connected();
}

static void main_preinit(void)
{
	unsigned int max_fds;

	random_init();
	/* Initialize SSL proxy so it can read certificate and private
	   key file. */
	ssl_proxy_init();

	/* set the number of fds we want to use. it may get increased or
	   decreased. leave a couple of extra fds for auth sockets and such.
	   normal connections each use one fd, but SSL connections use two */
	max_fds = MASTER_LISTEN_FD_FIRST + 16 +
		master_service_get_socket_count(service) +
		login_settings->login_max_connections*2;
	restrict_fd_limit(max_fds);
	io_loop_set_max_fd_count(current_ioloop, max_fds);

	i_assert(strcmp(login_settings->ssl, "no") == 0 || ssl_initialized);

	restrict_access_by_env(NULL, TRUE);
}

static void main_init(void)
{
	/* make sure we can't fork() */
	restrict_process_size((unsigned int)-1, 1);

	if (restrict_access_get_current_chroot() == NULL) {
		if (chdir("login") < 0)
			i_fatal("chdir(login) failed: %m");
	}

	auth_client = auth_client_new((unsigned int)getpid());
        auth_client_set_connect_notify(auth_client, auth_connect_notify, NULL);

	clients_init();
	master_auth_init(service);
}

static void main_deinit(void)
{
	ssl_proxy_deinit();
	login_proxy_deinit();

	if (auth_client != NULL)
		auth_client_free(&auth_client);
	clients_deinit();
	master_auth_deinit(service);
}

int main(int argc, char *argv[], char *envp[])
{
	const char *getopt_str;
	int c;

	//FIXME:is_inetd = getenv("DOVECOT_MASTER") == NULL;

	service = master_service_init(login_process_name, 0, argc, argv);
	master_service_init_log(service, t_strconcat(login_process_name, ": ",
						     NULL), 0);

        getopt_str = t_strconcat("DS", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'D':
			restrict_access_allow_coredumps(TRUE);
			break;
		case 'S':
			ssl_connections = TRUE;
			break;
		default:
			if (!master_service_parse_option(service, c, optarg))
				exit(FATAL_DEFAULT);
			break;
		}
	}

#if 0
	if (is_inetd) {
		/* running from inetd. create master process before
		   dropping privileges. */
		master_fd = master_connect(t_strcut(login_process_name, '-'));
	}
#endif

	process_title_init(argv, envp);
        login_settings = login_settings_read(service);

	main_preinit();
	master_service_init_finish(service);
	main_init();

	master_service_run(service, client_connected);
	main_deinit();
	master_service_deinit(&service);
        return 0;
}
