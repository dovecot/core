/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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
#include "master-service.h"
#include "password-scheme.h"
#include "mech.h"
#include "auth.h"
#include "auth-request-handler.h"
#include "auth-worker-server.h"
#include "auth-worker-client.h"
#include "auth-master-interface.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>

enum auth_socket_type {
	AUTH_SOCKET_UNKNOWN = 0,
	AUTH_SOCKET_CLIENT,
	AUTH_SOCKET_MASTER
};

struct master_service *service;
bool worker = FALSE, shutdown_request = FALSE;
time_t process_start_time;

static struct module *modules = NULL;
static struct auth *auth;
static struct auth_worker_client *worker_client;
static ARRAY_DEFINE(listen_fd_types, enum auth_socket_type);

static void main_preinit(struct auth_settings *set)
{
	/* Open /dev/urandom before chrooting */
	random_init();

	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();

	/* Initialize databases so their configuration files can be readable
	   only by root. Also load all modules here. */
	passdbs_init();
	userdbs_init();
	modules = module_dir_load(AUTH_MODULE_DIR, NULL, TRUE,
				  master_service_get_version_string(service));
	module_dir_init(modules);
	auth = auth_preinit(set);

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
	mech_init(auth->set);
	password_schemes_init();
	auth_init(auth);
	auth_request_handler_init();
	auth_master_connections_init();
	auth_client_connections_init();

	if (worker) {
		/* workers have only a single connection from the master
		   auth process */
		master_service_set_client_limit(service, 1);
	} else if (getenv("MASTER_AUTH_FD") != NULL) {
		(void)auth_master_connection_create(auth, MASTER_AUTH_FD);
	}
}

static void main_deinit(void)
{
	if (worker_client != NULL)
		auth_worker_client_unref(&worker_client);
	else
		auth_request_handler_flush_failures(TRUE);

	auth_client_connections_deinit();
	auth_master_connections_deinit();
        auth_worker_server_deinit();

	module_dir_unload(&modules);
	userdbs_deinit();
	passdbs_deinit();
	mech_deinit(auth->set);
	auth_deinit(&auth);

        password_schemes_deinit();
	sql_drivers_deinit();
	random_deinit();

	array_free(&listen_fd_types);
}

static void worker_connected(const struct master_service_connection *conn)
{
        auth_worker_client_create(auth, conn->fd);
}

static void client_connected(const struct master_service_connection *conn)
{
	enum auth_socket_type *type;

	if (worker) {
		worker_client = auth_worker_client_create(auth, conn->fd);
		return;
	}

	type = array_idx_modifiable(&listen_fd_types, conn->listen_fd);
	if (*type == AUTH_SOCKET_UNKNOWN) {
		/* figure out if this is a server or network socket by
		   checking the socket path name. */
		struct sockaddr_un sa;
		socklen_t addrlen = sizeof(sa);
		size_t len;

		if (getsockname(conn->listen_fd, (void *)&sa, &addrlen) < 0)
			i_fatal("getsockname(%d) failed: %m", conn->listen_fd);
		if (sa.sun_family != AF_UNIX) {
			i_fatal("getsockname(%d) isn't UNIX socket",
				conn->listen_fd);
		}

		len = strlen(sa.sun_path);
		if (len > 7 && strcmp(sa.sun_path + len - 7, "-master") == 0)
			*type = AUTH_SOCKET_MASTER;
		else
			*type = AUTH_SOCKET_CLIENT;
	}

	switch (*type) {
	case AUTH_SOCKET_MASTER:
		(void)auth_master_connection_create(auth, conn->fd);
		break;
	case AUTH_SOCKET_CLIENT:
		(void)auth_client_connection_create(auth, conn->fd);
		break;
	default:
		i_unreached();
	}
}

int main(int argc, char *argv[])
{
	const char *getopt_str, *auth_name = "default";
	int c;

	service = master_service_init("auth", 0, argc, argv);
	master_service_init_log(service, "auth: ", 0);

        getopt_str = t_strconcat("w", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'a':
			auth_name = optarg;
			break;
		case 'w':
			worker = TRUE;
			break;
		default:
			if (!master_service_parse_option(service, c, optarg))
				exit(FATAL_DEFAULT);
			break;
		}
	}

	main_preinit(auth_settings_read(service, auth_name));

	master_service_init_finish(service);
	main_init();
	master_service_run(service, worker ? worker_connected :
			   client_connected);
	main_deinit();
	master_service_deinit(&service);
        return 0;
}
