/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "randgen.h"
#include "auth.h"
#include "cookie.h"
#include "login-connection.h"
#include "userinfo.h"
#include "master.h"

#include <stdlib.h>
#include <syslog.h>

IOLoop ioloop;
static IO io_listen;

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void auth_accept(void *context __attr_unused__, int listen_fd,
			IO io __attr_unused__)
{
	int fd;

	fd = net_accept(listen_fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
	} else {
		(void)login_connection_create(fd);
	}
}

static void open_logfile(void)
{
	if (getenv("IMAP_USE_SYSLOG") != NULL)
		i_set_failure_syslog("imap-auth", LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(getenv("IMAP_LOGFILE"), "imap-auth");
		i_set_failure_timestamp_format(getenv("IMAP_LOGSTAMP"));
	}
}

static void drop_privileges(void)
{
	/* Log file or syslog opening probably requires roots */
	open_logfile();

	/* Open /dev/urandom before chrooting */
	random_init();

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(FALSE);
}

static void main_init(void)
{
	lib_init_signals(sig_quit);

	auth_init();
	cookies_init();
	login_connections_init();
	master_init();
	userinfo_init();

	io_listen = io_add(LOGIN_LISTEN_FD, IO_READ, auth_accept, NULL);
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	io_remove(io_listen);

	userinfo_deinit();
	master_deinit();
	login_connections_deinit();
	cookies_deinit();
	auth_deinit();

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
