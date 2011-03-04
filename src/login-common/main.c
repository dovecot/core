/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "randgen.h"
#include "process-title.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "master-auth.h"
#include "master-service.h"
#include "master-interface.h"
#include "client-common.h"
#include "access-lookup.h"
#include "anvil-client.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "login-proxy.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define DEFAULT_LOGIN_SOCKET "login"
#define AUTH_CLIENT_IDLE_TIMEOUT_MSECS (1000*60)

struct login_access_lookup {
	struct master_service_connection conn;
	struct io *io;

	char **sockets, **next_socket;
	struct access_lookup *access;
};

struct auth_client *auth_client;
struct master_auth *master_auth;
bool closing_down;
struct anvil_client *anvil;

const struct login_settings *global_login_settings;
void **global_other_settings;

static struct timeout *auth_client_to;
static bool shutting_down = FALSE;
static bool ssl_connections = FALSE;

static void login_access_lookup_next(struct login_access_lookup *lookup);

void login_refresh_proctitle(void)
{
	struct client *client = clients;
	const char *addr;

	if (!global_login_settings->verbose_proctitle)
		return;

	if (clients_get_count() == 0) {
		process_title_set("");
	} else if (clients_get_count() > 1 || client == NULL) {
		process_title_set(t_strdup_printf("[%u connections (%u TLS)]",
			clients_get_count(), ssl_proxy_get_count()));
	} else if ((addr = net_ip2addr(&client->ip)) != NULL) {
		process_title_set(t_strdup_printf(client->tls ?
						  "[%s TLS]" : "[%s]", addr));
	} else {
		process_title_set(client->tls ? "[TLS]" : "");
	}
}

static void auth_client_idle_timeout(struct auth_client *auth_client)
{
	auth_client_disconnect(auth_client);
	timeout_remove(&auth_client_to);
}

void login_client_destroyed(void)
{
	if (clients == NULL && auth_client_to == NULL) {
		auth_client_to = timeout_add(AUTH_CLIENT_IDLE_TIMEOUT_MSECS,
					     auth_client_idle_timeout,
					     auth_client);
	}
}

static void login_die(void)
{
	shutting_down = TRUE;
	login_proxy_kill_idle();

	if (!auth_client_is_connected(auth_client)) {
		/* we don't have auth client, and we might never get one */
		clients_destroy_all();
	}
}

static void
client_connected_finish(const struct master_service_connection *conn)
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

	pool = pool_alloconly_create("login client", 5*1024);
	set = login_settings_read(pool, &local_ip,
				  &conn->remote_ip, NULL, &other_sets);

	if (!ssl_connections && !conn->ssl) {
		client = client_create(conn->fd, FALSE, pool, set, other_sets,
				       &local_ip, &conn->remote_ip);
	} else {
		fd_ssl = ssl_proxy_alloc(conn->fd, &conn->remote_ip, set,
					 &proxy);
		if (fd_ssl == -1) {
			net_disconnect(conn->fd);
			pool_unref(&pool);
			master_service_client_connection_destroyed(master_service);
			return;
		}

		client = client_create(fd_ssl, TRUE, pool, set, other_sets,
				       &local_ip, &conn->remote_ip);
		client->ssl_proxy = proxy;
		ssl_proxy_set_client(proxy, client);
		ssl_proxy_start(proxy);
	}

	client->remote_port = conn->remote_port;
	client->local_port = local_port;

	if (auth_client_to != NULL)
		timeout_remove(&auth_client_to);
}

static void login_access_lookup_free(struct login_access_lookup *lookup)
{
	if (lookup->io != NULL)
		io_remove(&lookup->io);
	if (lookup->access != NULL)
		access_lookup_destroy(&lookup->access);
	if (lookup->conn.fd != -1) {
		if (close(lookup->conn.fd) < 0)
			i_error("close(client) failed: %m");
		master_service_client_connection_destroyed(master_service);
	}

	p_strsplit_free(default_pool, lookup->sockets);
	i_free(lookup);
}

static void login_access_callback(bool success, void *context)
{
	struct login_access_lookup *lookup = context;

	if (!success) {
		i_info("access(%s): Client refused (rip=%s)",
		       *lookup->next_socket,
		       net_ip2addr(&lookup->conn.remote_ip));
		login_access_lookup_free(lookup);
	} else {
		lookup->next_socket++;
		login_access_lookup_next(lookup);
	}
}

static void login_access_lookup_next(struct login_access_lookup *lookup)
{
	if (*lookup->next_socket == NULL) {
		/* last one */
		if (lookup->io != NULL)
			io_remove(&lookup->io);
		client_connected_finish(&lookup->conn);
		lookup->conn.fd = -1;
		login_access_lookup_free(lookup);
		return;
	}
	lookup->access = access_lookup(*lookup->next_socket, lookup->conn.fd,
				       login_binary.protocol,
				       login_access_callback, lookup);
	if (lookup->access == NULL)
		login_access_lookup_free(lookup);
}

static void client_input_error(struct login_access_lookup *lookup)
{
	char c;
	int ret;

	ret = recv(lookup->conn.fd, &c, 1, MSG_PEEK);
	if (ret <= 0) {
		i_info("access(%s): Client disconnected during lookup (rip=%s)",
		       *lookup->next_socket,
		       net_ip2addr(&lookup->conn.remote_ip));
		login_access_lookup_free(lookup);
	} else {
		/* actual input. stop listening until lookup is done. */
		io_remove(&lookup->io);
	}
}

static void client_connected(struct master_service_connection *conn)
{
	const char *access_sockets =
		global_login_settings->login_access_sockets;
	struct login_access_lookup *lookup;

	master_service_client_connection_accept(conn);

	/* make sure we're connected (or attempting to connect) to auth */
	auth_client_connect(auth_client);

	if (*access_sockets == '\0') {
		/* no access checks */
		client_connected_finish(conn);
		return;
	}

	lookup = i_new(struct login_access_lookup, 1);
	lookup->conn = *conn;
	lookup->io = io_add(conn->fd, IO_READ, client_input_error, lookup);
	lookup->sockets = p_strsplit_spaces(default_pool, access_sockets, " ");
	lookup->next_socket = lookup->sockets;

	login_access_lookup_next(lookup);
}

static void auth_connect_notify(struct auth_client *client ATTR_UNUSED,
				bool connected, void *context ATTR_UNUSED)
{
	if (connected)
		clients_notify_auth_connected();
	else if (shutting_down)
		clients_destroy_all();
}

static bool anvil_reconnect_callback(void)
{
	master_service_stop_new_connections(master_service);
	return FALSE;
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

	if (global_login_settings->mail_max_userip_connections > 0) {
		anvil = anvil_client_init("anvil", anvil_reconnect_callback, 0);
		if (anvil_client_connect(anvil, TRUE) < 0)
			i_fatal("Couldn't connect to anvil");
	}

	restrict_access_by_env(NULL, TRUE);
	if (allow_core_dumps)
		restrict_access_allow_coredumps(TRUE);
}

static void main_init(const char *login_socket)
{
	/* make sure we can't fork() */
	restrict_process_size((unsigned int)-1, 1);

	if (restrict_access_get_current_chroot() == NULL) {
		if (chdir("login") < 0)
			i_fatal("chdir(login) failed: %m");
	}

	master_service_set_avail_overflow_callback(master_service,
						   client_destroy_oldest);
	master_service_set_die_callback(master_service, login_die);

	auth_client = auth_client_init(login_socket, (unsigned int)getpid(),
				       FALSE);
        auth_client_set_connect_notify(auth_client, auth_connect_notify, NULL);
	master_auth = master_auth_init(master_service, login_binary.protocol);

	clients_init();
	login_proxy_init("proxy-notify");
}

static void main_deinit(void)
{
	ssl_proxy_deinit();
	login_proxy_deinit();

	clients_deinit();
	auth_client_deinit(&auth_client);
	master_auth_deinit(&master_auth);

	if (anvil != NULL)
		anvil_client_deinit(&anvil);
	if (auth_client_to != NULL)
		timeout_remove(&auth_client_to);
	login_settings_deinit();
}

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN |
		MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE;
	pool_t set_pool;
	bool allow_core_dumps = FALSE;
	const char *login_socket = DEFAULT_LOGIN_SOCKET;
	int c;

	master_service = master_service_init(login_binary.process_name,
					     service_flags, &argc, &argv, "DS");
	master_service_init_log(master_service, t_strconcat(
		login_binary.process_name, ": ", NULL));

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			allow_core_dumps = TRUE;
			break;
		case 'S':
			ssl_connections = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	if (argv[optind] != NULL)
		login_socket = argv[optind];

	login_process_preinit();

	set_pool = pool_alloconly_create("global login settings", 4096);
	global_login_settings =
		login_settings_read(set_pool, NULL, NULL, NULL,
				    &global_other_settings);

	/* main_preinit() needs to know the client limit, which is set by
	   this. so call it first. */
	master_service_init_finish(master_service);
	main_preinit(allow_core_dumps);
	main_init(login_socket);

	master_service_run(master_service, client_connected);
	main_deinit();
	pool_unref(&set_pool);
	master_service_deinit(&master_service);
        return 0;
}
