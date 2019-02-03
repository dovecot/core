/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "randgen.h"
#include "module-dir.h"
#include "process-title.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "master-auth.h"
#include "master-service.h"
#include "master-interface.h"
#include "iostream-ssl.h"
#include "client-common.h"
#include "access-lookup.h"
#include "anvil-client.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "master-service-ssl-settings.h"
#include "login-proxy.h"

#include <unistd.h>
#include <syslog.h>

#define AUTH_CLIENT_IDLE_TIMEOUT_MSECS (1000*60)

struct login_access_lookup {
	struct master_service_connection conn;
	struct io *io;

	char **sockets, **next_socket;
	struct access_lookup *access;
};

struct event *event_auth;
static struct event_category event_category_auth = {
	.name = "auth",
};

const struct login_binary *login_binary;
struct auth_client *auth_client;
struct master_auth *master_auth;
bool closing_down, login_debug;
struct anvil_client *anvil;
const char *login_rawlog_dir = NULL;
unsigned int initial_service_count;
struct login_module_register login_module_register;
ARRAY_TYPE(string) global_alt_usernames;
bool login_ssl_initialized;

const struct login_settings *global_login_settings;
const struct master_service_ssl_settings *global_ssl_settings;
void **global_other_settings;

const struct ip_addr *login_source_ips;
unsigned int login_source_ips_idx, login_source_ips_count;

static struct module *modules;
static struct timeout *auth_client_to;
static const char *post_login_socket;
static bool shutting_down = FALSE;
static bool ssl_connections = FALSE;
static bool auth_connected_once = FALSE;

static void login_access_lookup_next(struct login_access_lookup *lookup);

static bool get_first_client(struct client **client_r)
{
	struct client *client = clients;

	if (client == NULL)
		client = login_proxies_get_first_detached_client();
	if (client == NULL)
		client = clients_get_first_fd_proxy();
	*client_r = client;
	return client != NULL;
}

void login_refresh_proctitle(void)
{
	struct client *client;
	const char *addr;

	if (!global_login_settings->verbose_proctitle)
		return;

	/* clients_get_count() includes all the clients being served.
	   Inside that there are 3 groups:
	   1. pre-login clients
	   2. post-login clients being proxied to remote hosts
	   3. post-login clients being proxied to post-login processes
	   Currently the post-login proxying is done only for SSL/TLS
	   connections, so we're assuming that they're the same. */
	string_t *str = t_str_new(64);
	if (clients_get_count() == 0) {
		/* no clients */
	} else if (clients_get_count() > 1 || !get_first_client(&client)) {
		str_printfa(str, "[%u pre-login", clients_get_count() -
			    login_proxies_get_detached_count() -
			    clients_get_fd_proxies_count());
		if (login_proxies_get_detached_count() > 0) {
			/* show detached proxies only if they exist, so
			   non-proxy servers don't unnecessarily show them. */
			str_printfa(str, " + %u proxies",
				    login_proxies_get_detached_count());
		}
		if (clients_get_fd_proxies_count() > 0) {
			/* show post-login proxies only if they exist, so
			   proxy-only servers don't unnecessarily show them. */
			str_printfa(str, " + %u TLS proxies",
				    clients_get_fd_proxies_count());
		}
		str_append_c(str, ']');
	} else {
		str_append_c(str, '[');
		addr = net_ip2addr(&client->ip);
		if (addr[0] != '\0')
			str_printfa(str, "%s ", addr);
		if (client->fd_proxying)
			str_append(str, "TLS proxy");
		else if (client->destroyed)
			str_append(str, "proxy");
		else
			str_append(str, "pre-login");
		str_append_c(str, ']');
	}
	process_title_set(str_c(str));
}

static void auth_client_idle_timeout(struct auth_client *auth_client)
{
	i_assert(clients == NULL);

	auth_client_disconnect(auth_client, "idle disconnect");
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
	const struct login_settings *set;
	const struct master_service_ssl_settings *ssl_set;
	pool_t pool;
	void **other_sets;

	pool = pool_alloconly_create("login client", 8*1024);
	set = login_settings_read(pool, &conn->local_ip,
				  &conn->remote_ip, NULL, &ssl_set, &other_sets);

	client = client_alloc(conn->fd, pool, conn, set, ssl_set);
	if (ssl_connections || conn->ssl) {
		if (client_init_ssl(client) < 0) {
			client_unref(&client);
			net_disconnect(conn->fd);
			master_service_client_connection_destroyed(master_service);
			return;
		}
	}
	client_init(client, other_sets);

	timeout_remove(&auth_client_to);
}

static void login_access_lookup_free(struct login_access_lookup *lookup)
{
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
		io_remove(&lookup->io);
		client_connected_finish(&lookup->conn);
		lookup->conn.fd = -1;
		login_access_lookup_free(lookup);
		return;
	}
	lookup->access = access_lookup(*lookup->next_socket, lookup->conn.fd,
				       login_binary->protocol,
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
	if (conn->remote_ip.family != 0) {
		/* log the connection's IP address in case we crash. it's of
		   course possible that another earlier client causes the
		   crash, but this is better than nothing. */
		i_set_failure_send_ip(&conn->remote_ip);
	}

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
	if (connected) {
		auth_connected_once = TRUE;
		clients_notify_auth_connected();
	} else if (shutting_down)
		clients_destroy_all();
	else if (!auth_connected_once) {
		/* auth disconnected without having ever succeeded, so the
		   auth process is probably misconfigured. no point in
		   keeping the client connections hanging. */
		clients_destroy_all_reason("Disconnected: Auth process broken");
	}
}

static bool anvil_reconnect_callback(void)
{
	/* we got disconnected from anvil. we can't reconnect to it since we're
	   chrooted, so just die after we've finished handling the current
	   connections. */
	master_service_stop_new_connections(master_service);
	return FALSE;
}

void login_anvil_init(void)
{
	if (anvil != NULL)
		return;

	anvil = anvil_client_init("anvil", anvil_reconnect_callback, 0);
	if (anvil_client_connect(anvil, TRUE) < 0)
		i_fatal("Couldn't connect to anvil");
}

static const struct ip_addr *
parse_login_source_ips(const char *ips_str, unsigned int *count_r)
{
	ARRAY(struct ip_addr) ips;
	const char *const *tmp;
	struct ip_addr *tmp_ips;
	bool skip_nonworking = FALSE;
	unsigned int i, tmp_ips_count;
	int ret;

	if (ips_str[0] == '?') {
		/* try binding to the IP immediately. if it doesn't
		   work, skip it. (this allows using the same config file for
		   all the servers.) */
		skip_nonworking = TRUE;
		ips_str++;
	}
	t_array_init(&ips, 4);
	for (tmp = t_strsplit_spaces(ips_str, ", "); *tmp != NULL; tmp++) {
		ret = net_gethostbyname(*tmp, &tmp_ips, &tmp_ips_count);
		if (ret != 0) {
			i_error("login_source_ips: net_gethostbyname(%s) failed: %s",
				*tmp, net_gethosterror(ret));
			continue;
		}
		for (i = 0; i < tmp_ips_count; i++) {
			if (skip_nonworking && net_try_bind(&tmp_ips[i]) < 0)
				continue;
			array_push_back(&ips, &tmp_ips[i]);
		}
	}
	return array_get(&ips, count_r);
}

static void login_load_modules(void)
{
	struct module_dir_load_settings mod_set;

	if (global_login_settings->login_plugins[0] == '\0')
		return;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.binary_name = login_binary->process_name;
	mod_set.setting_name = "login_plugins";
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = login_debug;

	modules = module_dir_load(global_login_settings->login_plugin_dir,
				  global_login_settings->login_plugins,
				  &mod_set);
	module_dir_init(modules);
}

static void login_ssl_init(void)
{
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (strcmp(global_ssl_settings->ssl, "no") == 0)
		return;

	master_service_ssl_settings_to_iostream_set(global_ssl_settings,
		pool_datastack_create(),
		MASTER_SERVICE_SSL_SETTINGS_TYPE_SERVER, &ssl_set);
	if (io_stream_ssl_global_init(&ssl_set, &error) < 0)
		i_fatal("Failed to initialize SSL library: %s", error);
	login_ssl_initialized = TRUE;
}

static void main_preinit(void)
{
	unsigned int max_fds;

	/* Initialize SSL proxy so it can read certificate and private
	   key file. */
	login_ssl_init();
	dsasl_clients_init();
	client_common_init();

	/* set the number of fds we want to use. it may get increased or
	   decreased. leave a couple of extra fds for auth sockets and such.

	   worst case each connection can use:

	    - 1 for client
	    - 1 for login proxy
	    - 2 for client-side ssl proxy
	    - 2 for server-side ssl proxy (with login proxy)

	   However, login process nowadays supports plugins, there are rawlogs
	   and so on. Don't enforce the fd limit anymore, but use this value
	   for optimizing the ioloop's fd table size.
	*/
	max_fds = MASTER_LISTEN_FD_FIRST + 16 +
		master_service_get_socket_count(master_service) +
		master_service_get_client_limit(master_service)*6;
	io_loop_set_max_fd_count(current_ioloop, max_fds);

	i_assert(strcmp(global_ssl_settings->ssl, "no") == 0 ||
		 login_ssl_initialized);

	if (global_login_settings->mail_max_userip_connections > 0)
		login_anvil_init();

	/* read the login_source_ips before chrooting so it can access
	   /etc/hosts */
	login_source_ips = parse_login_source_ips(global_login_settings->login_source_ips,
						  &login_source_ips_count);
	if (login_source_ips_count > 0) {
		/* randomize the initial index in case service_count=1
		   (although in that case it's unlikely this setting is
		   even used..) */
		login_source_ips_idx = i_rand_limit(login_source_ips_count);
	}

	login_load_modules();

	restrict_access_by_env(0, NULL);
	if (login_debug)
		restrict_access_allow_coredumps(TRUE);
	initial_service_count = master_service_get_service_count(master_service);

	if (restrict_access_get_current_chroot() == NULL) {
		if (chdir("login") < 0)
			i_fatal("chdir(login) failed: %m");
	}

	if (login_rawlog_dir != NULL &&
	    access(login_rawlog_dir, W_OK | X_OK) < 0) {
		i_error("access(%s, wx) failed: %m - disabling rawlog",
			login_rawlog_dir);
		login_rawlog_dir = NULL;
	}
}

static void main_init(const char *login_socket)
{
	/* make sure we can't fork() */
	restrict_process_count(1);

	event_auth = event_create(NULL);
	event_set_forced_debug(event_auth, global_login_settings->auth_debug);
	event_add_category(event_auth, &event_category_auth);

	i_array_init(&global_alt_usernames, 4);
	master_service_set_avail_overflow_callback(master_service,
						   client_destroy_oldest);
	master_service_set_die_callback(master_service, login_die);

	auth_client = auth_client_init(login_socket, (unsigned int)getpid(),
				       FALSE);
	auth_client_connect(auth_client);
        auth_client_set_connect_notify(auth_client, auth_connect_notify, NULL);
	master_auth = master_auth_init(master_service, post_login_socket);

	login_binary->init();

	login_proxy_init(global_login_settings->login_proxy_notify_path);
}

static void main_deinit(void)
{
	client_destroy_fd_proxies();
	ssl_iostream_context_cache_free();
	login_proxy_deinit();

	login_binary->deinit();
	module_dir_unload(&modules);
	auth_client_deinit(&auth_client);
	master_auth_deinit(&master_auth);

	char **strp;
	array_foreach_modifiable(&global_alt_usernames, strp)
		i_free(*strp);
	array_free(&global_alt_usernames);

	if (anvil != NULL)
		anvil_client_deinit(&anvil);
	timeout_remove(&auth_client_to);
	client_common_deinit();
	dsasl_clients_deinit();
	login_settings_deinit();
	event_unref(&event_auth);
}

int login_binary_run(const struct login_binary *binary,
		     int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN |
		MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE |
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	pool_t set_pool;
	const char *login_socket;
	int c;

	login_binary = binary;
	login_socket = binary->default_login_socket != NULL ?
		binary->default_login_socket : LOGIN_DEFAULT_SOCKET;
	post_login_socket = binary->protocol;

	master_service = master_service_init(login_binary->process_name,
					     service_flags, &argc, &argv,
					     "Dl:R:S");
	master_service_init_log(master_service, t_strconcat(
		login_binary->process_name, ": ", NULL));

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			login_debug = TRUE;
			break;
		case 'l':
			post_login_socket = optarg;
			break;
		case 'R':
			login_rawlog_dir = optarg;
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

	login_binary->preinit();

	set_pool = pool_alloconly_create("global login settings", 4096);
	global_login_settings =
		login_settings_read(set_pool, NULL, NULL, NULL,
				    &global_ssl_settings,
				    &global_other_settings);

	main_preinit();
	master_service_init_finish(master_service);
	main_init(login_socket);

	master_service_run(master_service, client_connected);
	main_deinit();
	pool_unref(&set_pool);
	master_service_deinit(&master_service);
        return 0;
}
