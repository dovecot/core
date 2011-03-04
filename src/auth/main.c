/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "child-wait.h"
#include "sql-api.h"
#include "module-dir.h"
#include "randgen.h"
#include "process-title.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "password-scheme.h"
#include "passdb-cache.h"
#include "mech.h"
#include "auth.h"
#include "auth-penalty.h"
#include "auth-request-handler.h"
#include "auth-worker-server.h"
#include "auth-worker-client.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"

#include <unistd.h>

#define AUTH_PENALTY_ANVIL_PATH "anvil-auth-penalty"

enum auth_socket_type {
	AUTH_SOCKET_UNKNOWN = 0,
	AUTH_SOCKET_CLIENT,
	AUTH_SOCKET_LOGIN_CLIENT,
	AUTH_SOCKET_MASTER,
	AUTH_SOCKET_USERDB
};

bool worker = FALSE, shutdown_request = FALSE;
time_t process_start_time;
struct auth_penalty *auth_penalty;

static pool_t auth_set_pool;
static struct module *modules = NULL;
static struct mechanisms_register *mech_reg;
static ARRAY_DEFINE(listen_fd_types, enum auth_socket_type);

void auth_refresh_proctitle(void)
{
	if (!global_auth_settings->verbose_proctitle)
		return;

	process_title_set(t_strdup_printf(
		"[%u wait, %u passdb, %u userdb]",
		auth_request_state_count[AUTH_REQUEST_STATE_NEW] +
		auth_request_state_count[AUTH_REQUEST_STATE_MECH_CONTINUE] +
		auth_request_state_count[AUTH_REQUEST_STATE_FINISHED],
		auth_request_state_count[AUTH_REQUEST_STATE_PASSDB],
		auth_request_state_count[AUTH_REQUEST_STATE_USERDB]));
}

static const char *const *read_global_settings(void)
{
	struct master_service_settings_output set_output;
	const char **services;
	unsigned int i, count;

	auth_set_pool = pool_alloconly_create("auth settings", 8192);
	global_auth_settings =
		auth_settings_read(NULL, auth_set_pool, &set_output);

	/* strdup() the service names, because they're allocated from
	   set parser pool, and we'll later clear it. */
	count = str_array_length(set_output.specific_services);
	services = p_new(auth_set_pool, const char *, count + 1);
	for (i = 0; i < count; i++) {
		services[i] = p_strdup(auth_set_pool,
				       set_output.specific_services[i]);
	}
	return services;
}

static void main_preinit(void)
{
	struct module_dir_load_settings mod_set;
	const char *const *services;

	/* Open /dev/urandom before chrooting */
	random_init();

	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();

	/* Initialize databases so their configuration files can be readable
	   only by root. Also load all modules here. */
	passdbs_init();
	userdbs_init();
	/* init schemes before plugins are loaded */
	password_schemes_init();

	services = read_global_settings();

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = global_auth_settings->debug;

	modules = module_dir_load(AUTH_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	if (!worker)
		auth_penalty = auth_penalty_init(AUTH_PENALTY_ANVIL_PATH);
	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	auths_preinit(global_auth_settings, auth_set_pool,
		      mech_reg, services);

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	i_array_init(&listen_fd_types, 8);

        process_start_time = ioloop_time;

	/* If auth caches aren't used, just ignore these signals */
	lib_signals_ignore(SIGHUP, TRUE);
	lib_signals_ignore(SIGUSR2, TRUE);

	child_wait_init();
	auth_worker_server_init();
	auths_init();
	auth_request_handler_init();
	auth_master_connections_init();
	auth_client_connections_init();

	if (worker) {
		/* workers have only a single connection from the master
		   auth process */
		master_service_set_client_limit(master_service, 1);
	} else {
		/* caching is handled only by the main auth process */
		passdb_cache_init(global_auth_settings);
	}
	auth_refresh_proctitle();
}

static void main_deinit(void)
{
	if (auth_penalty != NULL) {
		/* cancel all pending anvil penalty lookups */
		auth_penalty_deinit(&auth_penalty);
	}
	/* deinit auth workers, which aborts pending requests */
        auth_worker_server_deinit();
	/* deinit passdbs and userdbs. it aborts any pending async requests. */
	auths_deinit();
	/* flush pending requests */
	auth_request_handler_deinit();
	/* there are no more auth requests */
	auths_free();

	auth_client_connections_deinit();
	auth_master_connections_deinit();

	if (auth_worker_client != NULL)
		auth_worker_client_destroy(&auth_worker_client);

	mech_register_deinit(&mech_reg);
	mech_deinit(global_auth_settings);

	/* allow modules to unregister their dbs/drivers/etc. before freeing
	   the whole data structures containing them. */
	module_dir_unload(&modules);

	userdbs_deinit();
	passdbs_deinit();
	passdb_cache_deinit();
        password_schemes_deinit();
	sql_drivers_deinit();
	random_deinit();

	array_free(&listen_fd_types);
	pool_unref(&auth_set_pool);
}

static void worker_connected(struct master_service_connection *conn)
{
	if (auth_worker_client != NULL) {
		i_error("Auth workers can handle only a single client");
		return;
	}

	master_service_client_connection_accept(conn);
	(void)auth_worker_client_create(auth_find_service(NULL), conn->fd);
}

static enum auth_socket_type
auth_socket_type_get(int listen_fd)
{
	const char *path, *name, *suffix;

	/* figure out if this is a server or network socket by
	   checking the socket path name. */
	if (net_getunixname(listen_fd, &path) < 0) {
		if (errno != ENOTSOCK)
			i_fatal("getunixname(%d) failed: %m", listen_fd);
		/* not UNIX socket. let's just assume it's an
		   auth client. */
		return AUTH_SOCKET_CLIENT;
	}

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;

	suffix = strrchr(name, '-');
	if (suffix == NULL)
		suffix = name;
	else
		suffix++;

	if (strcmp(suffix, "login") == 0)
		return AUTH_SOCKET_LOGIN_CLIENT;
	else if (strcmp(suffix, "master") == 0)
		return AUTH_SOCKET_MASTER;
	else if (strcmp(suffix, "userdb") == 0)
		return AUTH_SOCKET_USERDB;
	else
		return AUTH_SOCKET_CLIENT;
}

static void client_connected(struct master_service_connection *conn)
{
	enum auth_socket_type *type;
	struct auth *auth;

	type = array_idx_modifiable(&listen_fd_types, conn->listen_fd);
	if (*type == AUTH_SOCKET_UNKNOWN)
		*type = auth_socket_type_get(conn->listen_fd);

	auth = auth_find_service(NULL);
	switch (*type) {
	case AUTH_SOCKET_MASTER:
		(void)auth_master_connection_create(auth, conn->fd, FALSE);
		break;
	case AUTH_SOCKET_USERDB:
		(void)auth_master_connection_create(auth, conn->fd, TRUE);
		break;
	case AUTH_SOCKET_LOGIN_CLIENT:
		(void)auth_client_connection_create(auth, conn->fd, TRUE);
		break;
	case AUTH_SOCKET_CLIENT:
		(void)auth_client_connection_create(auth, conn->fd, FALSE);
		break;
	default:
		i_unreached();
	}
	master_service_client_connection_accept(conn);
}

static void auth_die(void)
{
	/* do nothing. auth clients should disconnect soon. */
}

int main(int argc, char *argv[])
{
	int c;

	master_service = master_service_init("auth", 0, &argc, &argv, "w");
	master_service_init_log(master_service, "auth: ");

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'w':
			worker = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	main_preinit();
	master_service_init_finish(master_service);
	master_service_set_die_callback(master_service, auth_die);
	main_init();
	master_service_run(master_service, worker ? worker_connected :
			   client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
