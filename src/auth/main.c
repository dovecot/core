/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
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
#include <syslog.h>

struct ioloop *ioloop;
int verbose = FALSE, verbose_debug = FALSE;

static struct auth_master_connection *master;
static struct io *io_listen;

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void auth_accept(void *context __attr_unused__)
{
	int fd;

	fd = net_accept(LOGIN_LISTEN_FD, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
	} else {
		net_set_nonblock(fd, TRUE);
		(void)auth_client_connection_create(master, fd);
	}
}

static void drop_privileges(void)
{
	i_set_failure_internal();

	/* Open /dev/urandom before chrooting */
	random_init();

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(FALSE);
}

static void main_init(void)
{
	const char *env;
	unsigned int pid;

	lib_init_signals(sig_quit);

	verbose = getenv("VERBOSE") != NULL;
	verbose_debug = getenv("VERBOSE_DEBUG") != NULL;

	env = getenv("AUTH_PROCESS");
	if (env == NULL)
		i_fatal("AUTH_PROCESS environment is unset");

	pid = atoi(env);
	if (pid == 0)
		i_fatal("AUTH_PROCESS can't be 0");

	mech_init();
	userdb_init();
	passdb_init();

	io_listen = io_add(LOGIN_LISTEN_FD, IO_READ, auth_accept, NULL);

	/* initialize master last - it sends the "we're ok" notification */
	master = auth_master_connection_new(MASTER_SOCKET_FD, pid);
	auth_client_connections_init(master);
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	io_remove(io_listen);

	auth_client_connections_deinit(master);

	passdb_deinit();
	userdb_deinit();
	mech_deinit();

	auth_master_connection_free(master);
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
