/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "ioloop.h"
#include "network.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "randgen.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

struct ioloop *ioloop;
int verbose = FALSE, verbose_debug = FALSE;

static buffer_t *masters_buf;

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void open_logfile(void)
{
	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

	if (getenv("USE_SYSLOG") != NULL)
		i_set_failure_syslog("dovecot-auth", LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), "dovecot-auth");
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static void drop_privileges(void)
{
	open_logfile();

	/* Open /dev/urandom before chrooting */
	random_init();

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(FALSE);
}

static void master_add_unix_listeners(struct auth_master_connection *master,
				      const char *sockets_list)
{
	const char *const *sockets;
	int fd;

	sockets = t_strsplit(sockets_list, ":");
	while (*sockets != NULL) {
		fd = net_listen_unix(*sockets);
		if (fd == -1) {
			i_fatal("net_listen_unix(%s) failed: %m",
				*sockets);
		}

		auth_master_connection_add_listener(master, fd, *sockets);
		sockets++;
	}
}

static void main_init(void)
{
	struct auth_master_connection *master, **master_p;
	size_t i, size;
	const char *env;
	unsigned int pid;

	lib_init_signals(sig_quit);

	verbose = getenv("VERBOSE") != NULL;
	verbose_debug = getenv("VERBOSE_DEBUG") != NULL;

	mech_init();
	userdb_init();
	passdb_init();

	masters_buf = buffer_create_dynamic(default_pool, 64, (size_t)-1);

	env = getenv("AUTH_PROCESS");
	if (env == NULL) {
		/* starting standalone */
		env = getenv("AUTH_SOCKETS");
		if (env == NULL)
			i_fatal("AUTH_SOCKETS environment not set");

		switch (fork()) {
		case -1:
			i_fatal("fork() failed: %m");
		case 0:
			break;
		default:
			exit(0);
		}

		if (setsid() < 0)
			i_fatal("setsid() failed: %m");

		if (chdir("/") < 0)
			i_fatal("chdir(/) failed: %m");
       } else {
		pid = atoi(env);
		if (pid == 0)
			i_fatal("AUTH_PROCESS can't be 0");

		master = auth_master_connection_new(MASTER_SOCKET_FD, pid);
		auth_master_connection_add_listener(master, LOGIN_LISTEN_FD,
						    NULL);
		auth_client_connections_init(master);
		buffer_append(masters_buf, &master, sizeof(master));

		/* accept also alternative listeners under dummy master */
		env = getenv("AUTH_SOCKETS");
	}

	if (env != NULL) {
		master = auth_master_connection_new(-1, 0);
		master_add_unix_listeners(master, env);
		auth_client_connections_init(master);
		buffer_append(masters_buf, &master, sizeof(master));
	}

	/* everything initialized, notify masters that all is well */
	master_p = buffer_get_modifyable_data(masters_buf, &size);
	size /= sizeof(*master_p);
	for (i = 0; i < size; i++)
		auth_master_connection_send_handshake(master_p[i]);
}

static void main_deinit(void)
{
	struct auth_master_connection **master;
	size_t i, size;

        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	master = buffer_get_modifyable_data(masters_buf, &size);
	size /= sizeof(*master);
	for (i = 0; i < size; i++) {
		auth_client_connections_deinit(master[i]);
		auth_master_connection_free(master[i]);
	}

	passdb_deinit();
	userdb_deinit();
	mech_deinit();

	random_deinit();

	closelog();
}

int main(int argc __attr_unused__, char *argv[] __attr_unused__)
{
#ifdef DEBUG
        fd_debug_verify_leaks(4, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
