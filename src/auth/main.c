/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
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
#include "dict.h"
#include "password-scheme.h"
#include "passdb-cache.h"
#include "mech.h"
#include "auth.h"
#include "auth-penalty.h"
#include "auth-token.h"
#include "auth-request-handler.h"
#include "auth-request-stats.h"
#include "auth-worker-server.h"
#include "auth-worker-client.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"
#include "auth-policy.h"

#include <unistd.h>
#include <sys/stat.h>

#define AUTH_PENALTY_ANVIL_PATH "anvil-auth-penalty"

enum auth_socket_type {
	AUTH_SOCKET_UNKNOWN = 0,
	AUTH_SOCKET_CLIENT,
	AUTH_SOCKET_LOGIN_CLIENT,
	AUTH_SOCKET_MASTER,
	AUTH_SOCKET_USERDB,
	AUTH_SOCKET_POSTFIX,
	AUTH_SOCKET_TOKEN,
	AUTH_SOCKET_TOKEN_LOGIN
};

struct auth_socket_listener {
	enum auth_socket_type type;
	struct stat st;
	char *path;
};

bool worker = FALSE, worker_restart_request = FALSE;
time_t process_start_time;
struct auth_penalty *auth_penalty;

static pool_t auth_set_pool;
static struct module *modules = NULL;
static struct mechanisms_register *mech_reg;
static ARRAY(struct auth_socket_listener) listeners;

void auth_refresh_proctitle(void)
{
	if (!global_auth_settings->verbose_proctitle || worker)
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

static enum auth_socket_type
auth_socket_type_get(const char *path)
{
	const char *name, *suffix;

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
	else if (strcmp(suffix, "postmap") == 0)
		return AUTH_SOCKET_POSTFIX;
	else if (strcmp(suffix, "token") == 0)
		return AUTH_SOCKET_TOKEN;
	else if (strcmp(suffix, "tokenlogin") == 0)
		return AUTH_SOCKET_TOKEN_LOGIN;
	else
		return AUTH_SOCKET_CLIENT;
}

static void listeners_init(void)
{
	unsigned int i, n;
	const char *path;

	i_array_init(&listeners, 8);
	n = master_service_get_socket_count(master_service);
	for (i = 0; i < n; i++) {
		int fd = MASTER_LISTEN_FD_FIRST + i;
		struct auth_socket_listener *l;

		l = array_idx_get_space(&listeners, fd);
		if (net_getunixname(fd, &path) < 0) {
			if (errno != ENOTSOCK)
				i_fatal("getunixname(%d) failed: %m", fd);
			/* not a unix socket, set its name and type lazily */
		} else {
			l->type = auth_socket_type_get(path);
			l->path = i_strdup(path);
			if (l->type == AUTH_SOCKET_USERDB) {
				if (stat(path, &l->st) < 0)
					i_error("stat(%s) failed: %m", path);
			}
		}
	}
}

static bool auth_module_filter(const char *name, void *context ATTR_UNUSED)
{
	if (str_begins(name, "authdb_") ||
	    str_begins(name, "mech_")) {
		/* this is lazily loaded */
		return FALSE;
	}
	return TRUE;
}

static void main_preinit(void)
{
	struct module_dir_load_settings mod_set;
	const char *const *services;

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

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = global_auth_settings->debug;
	mod_set.filter_callback = auth_module_filter;

	modules = module_dir_load(AUTH_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	if (!worker)
		auth_penalty = auth_penalty_init(AUTH_PENALTY_ANVIL_PATH);
	auth_request_stats_init();
	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	dict_drivers_register_builtin();
	auths_preinit(global_auth_settings, auth_set_pool,
		      mech_reg, services);

	listeners_init();
	if (!worker)
		auth_token_init();

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

void auth_module_load(const char *names)
{
	struct module_dir_load_settings mod_set;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = global_auth_settings->debug;
	mod_set.ignore_missing = TRUE;

	modules = module_dir_load_missing(modules, AUTH_MODULE_DIR, names,
					  &mod_set);
	module_dir_init(modules);
}

static void main_init(void)
{
        process_start_time = ioloop_time;

	/* If auth caches aren't used, just ignore these signals */
	lib_signals_ignore(SIGHUP, TRUE);
	lib_signals_ignore(SIGUSR2, TRUE);

	/* set proctitles before init()s, since they may set them to error */
	auth_refresh_proctitle();
	auth_worker_refresh_proctitle("");

	child_wait_init();
	auth_worker_server_init();
	auths_init();
	auth_request_handler_init();
	auth_policy_init();

	if (worker) {
		/* workers have only a single connection from the master
		   auth process */
		master_service_set_client_limit(master_service, 1);
	} else {
		/* caching is handled only by the main auth process */
		passdb_cache_init(global_auth_settings);
	}
}

static void main_deinit(void)
{
	struct auth_socket_listener *l;

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
	dict_drivers_unregister_builtin();

	auth_token_deinit();

	auth_client_connections_destroy_all();
	auth_master_connections_destroy_all();
	auth_worker_connections_destroy_all();

	auth_policy_deinit();
	mech_register_deinit(&mech_reg);
	mech_deinit(global_auth_settings);

	/* allow modules to unregister their dbs/drivers/etc. before freeing
	   the whole data structures containing them. */
	module_dir_unload(&modules);

	userdbs_deinit();
	passdbs_deinit();
	passdb_cache_deinit();
        password_schemes_deinit();
	auth_request_stats_deinit();

	sql_drivers_deinit();
	child_wait_deinit();

	array_foreach_modifiable(&listeners, l)
		i_free(l->path);
	array_free(&listeners);
	pool_unref(&auth_set_pool);
}

static void worker_connected(struct master_service_connection *conn)
{
	if (auth_worker_has_client()) {
		i_error("Auth workers can handle only a single client");
		return;
	}

	master_service_client_connection_accept(conn);
	(void)auth_worker_client_create(auth_default_service(), conn);
}

static void client_connected(struct master_service_connection *conn)
{
	struct auth_socket_listener *l;
	struct auth *auth;

	l = array_idx_modifiable(&listeners, conn->listen_fd);
	if (l->type == AUTH_SOCKET_UNKNOWN) {
		/* first connection from inet socket, figure out its type
		   from the listener name */
		l->type = auth_socket_type_get(conn->name);
		l->path = i_strdup(conn->name);
	}
	auth = auth_default_service();
	switch (l->type) {
	case AUTH_SOCKET_MASTER:
		(void)auth_master_connection_create(auth, conn->fd,
						    l->path, NULL, FALSE);
		break;
	case AUTH_SOCKET_USERDB:
		(void)auth_master_connection_create(auth, conn->fd,
						    l->path, &l->st, TRUE);
		break;
	case AUTH_SOCKET_POSTFIX:
		e_error(auth_event, "postfix socketmap is no longer supported");
		break;
	case AUTH_SOCKET_LOGIN_CLIENT:
		auth_client_connection_create(auth, conn->fd, TRUE, FALSE);
		break;
	case AUTH_SOCKET_CLIENT:
		auth_client_connection_create(auth, conn->fd, FALSE, FALSE);
		break;
	case AUTH_SOCKET_TOKEN_LOGIN:
		auth_client_connection_create(auth, conn->fd, TRUE, TRUE);
		break;
	case AUTH_SOCKET_TOKEN:
		auth_client_connection_create(auth, conn->fd, FALSE, TRUE);
		break;
	default:
		i_unreached();
	}
	master_service_client_connection_accept(conn);
}

static void auth_die(void)
{
	if (!worker) {
		/* do nothing. auth clients should disconnect soon. */
	} else {
		/* ask auth master to disconnect us */
		auth_worker_client_send_shutdown();
	}
}

int main(int argc, char *argv[])
{
	int c;
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;

	master_service = master_service_init("auth", service_flags, &argc, &argv, "w");
	master_service_init_log(master_service, "auth: ");

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'w':
			master_service_init_log_with_pid(master_service);
			worker = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	main_preinit();
	master_service_set_die_callback(master_service, auth_die);
	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, worker ? worker_connected :
			   client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
