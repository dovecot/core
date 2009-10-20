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
struct master_auth *master_auth;
bool closing_down;
int anvil_fd = -1;

const struct login_settings *global_login_settings;
void **global_other_settings;

static bool ssl_connections = FALSE;

static void client_connected(const struct master_service_connection *conn)
{
	struct client *client;
	struct ssl_proxy *proxy;
	struct ip_addr local_ip;
	const struct login_settings *set;
	unsigned int local_port;
	pool_t pool;
	int fd_ssl;
	void **other_sets;

	if (net_getsockname(conn->fd, &local_ip, &local_port) < 0) {
		memset(&local_ip, 0, sizeof(local_ip));
		local_port = 0;
	}

	pool = pool_alloconly_create("login client", 3*1024);
	set = login_settings_read(master_service, pool, &local_ip,
				  &conn->remote_ip, &other_sets);

	if (!ssl_connections && !conn->ssl) {
		client = client_create(conn->fd, FALSE, pool, set, other_sets,
				       &local_ip, &conn->remote_ip);
	} else {
		fd_ssl = ssl_proxy_new(conn->fd, &conn->remote_ip, set, &proxy);
		if (fd_ssl == -1) {
			net_disconnect(conn->fd);
			pool_unref(&pool);
			return;
		}

		client = client_create(fd_ssl, TRUE, pool, set, other_sets,
				       &local_ip, &conn->remote_ip);
		client->ssl_proxy = proxy;
		ssl_proxy_set_client(proxy, client);
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

static int anvil_connect(void)
{
#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
	int i = 0, fd;

	while ((fd = net_connect_unix("anvil")) == -1) {
		if (errno != EAGAIN || ++i == 3)
			i_fatal("net_connect_unix(anvil) failed: %m");
		sleep(1);
	}
	net_set_nonblock(fd, FALSE);

	if (write(fd, ANVIL_HANDSHAKE, strlen(ANVIL_HANDSHAKE)) < 0)
		i_fatal("write(anvil) failed: %m");
	return fd;
}

static void main_preinit(bool allow_core_dumps)
{
	unsigned int max_fds;

	random_init();
	/* Initialize SSL proxy so it can read certificate and private
	   key file. */
	ssl_proxy_init();

	/* set the number of fds we want to use. it may get increased or
	   decreased. leave a couple of extra fds for auth sockets and such.

	   worst case each connection can use:

	    - 1 for client
	    - 1 for login proxy
	    - 2 for client-side ssl proxy
	    - 2 for server-side ssl proxy (with login proxy)
	*/
	max_fds = MASTER_LISTEN_FD_FIRST + 16 +
		master_service_get_socket_count(master_service) +
		master_service_get_client_limit(master_service)*6;
	restrict_fd_limit(max_fds);
	io_loop_set_max_fd_count(current_ioloop, max_fds);

	i_assert(strcmp(global_login_settings->ssl, "no") == 0 ||
		 ssl_initialized);

	if (global_login_settings->mail_max_userip_connections > 0)
		anvil_fd = anvil_connect();

	restrict_access_by_env(NULL, TRUE);
	if (allow_core_dumps)
		restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	/* make sure we can't fork() */
	restrict_process_size((unsigned int)-1, 1);

	if (restrict_access_get_current_chroot() == NULL) {
		if (chdir("login") < 0)
			i_fatal("chdir(login) failed: %m");
	}

	master_service_set_avail_overflow_callback(master_service,
						   client_destroy_oldest);

	auth_client = auth_client_init("auth", (unsigned int)getpid(), FALSE);
        auth_client_set_connect_notify(auth_client, auth_connect_notify, NULL);
	master_auth = master_auth_init(master_service, login_protocol);

	clients_init();
	login_proxy_init();
}

static void main_deinit(void)
{
	ssl_proxy_deinit();
	login_proxy_deinit();

	if (auth_client != NULL)
		auth_client_deinit(&auth_client);
	clients_deinit();
	master_auth_deinit(&master_auth);

	if (anvil_fd != -1) {
		if (close(anvil_fd) < 0)
			i_error("close(anvil) failed: %m");
	}
}

int main(int argc, char *argv[], char *envp[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN |
		MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE;
	const char *getopt_str;
	pool_t set_pool;
	bool allow_core_dumps = FALSE;
	int c;

	master_service = master_service_init(login_process_name, service_flags,
					     argc, argv);
	master_service_init_log(master_service, t_strconcat(
		login_process_name, ": ", NULL));

        getopt_str = t_strconcat("DS", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'D':
			allow_core_dumps = TRUE;
			break;
		case 'S':
			ssl_connections = TRUE;
			break;
		default:
			if (!master_service_parse_option(master_service,
							 c, optarg))
				exit(FATAL_DEFAULT);
			break;
		}
	}

	login_process_preinit();

	process_title_init(argv, envp);
	set_pool = pool_alloconly_create("global login settings", 4096);
	global_login_settings =
		login_settings_read(master_service, set_pool, NULL, NULL,
				    &global_other_settings);

	/* main_preinit() needs to know the client limit, which is set by
	   this. so call it first. */
	master_service_init_finish(master_service);
	main_preinit(allow_core_dumps);
	main_init();

	master_service_run(master_service, client_connected);
	main_deinit();
	pool_unref(&set_pool);
	master_service_deinit(&master_service);
        return 0;
}
