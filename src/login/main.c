/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "auth-connection.h"
#include "master.h"
#include "client.h"
#include "ssl-proxy.h"

#include <stdlib.h>
#include <syslog.h>

IOLoop ioloop;
int disable_plaintext_auth;
unsigned int max_logging_users;

static IO io_imap, io_imaps;

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void login_accept(void *context __attr_unused__, int listen_fd,
			 IO io __attr_unused__)
{
	IPADDR addr;
	int fd;

	fd = net_accept(listen_fd, &addr, NULL);
	if (fd == -1)
		return;

	(void)client_create(fd, &addr);
}

static void login_accept_ssl(void *context __attr_unused__, int listen_fd,
			     IO io __attr_unused__)
{
	Client *client;
	IPADDR addr;
	int fd, fd_ssl;

	fd = net_accept(listen_fd, &addr, NULL);
	if (fd == -1)
		return;

	fd_ssl = ssl_proxy_new(fd);
	if (fd_ssl == -1)
		net_disconnect(fd);
	else {
		client = client_create(fd_ssl, &addr);
		client->tls = TRUE;
	}
}

static void main_init(void)
{
	const char *logfile, *value;

	lib_init_signals(sig_quit);

	logfile = getenv("IMAP_LOGFILE");
	if (logfile == NULL) {
		/* open the syslog immediately so chroot() won't
		   break logging */
		openlog("imap-login", LOG_NDELAY, LOG_MAIL);

		i_set_panic_handler(i_syslog_panic_handler);
		i_set_fatal_handler(i_syslog_fatal_handler);
		i_set_error_handler(i_syslog_error_handler);
		i_set_warning_handler(i_syslog_warning_handler);
	} else {
		/* log failures into specified log file */
		i_set_failure_file(logfile, "imap-login");
		i_set_failure_timestamp_format(getenv("IMAP_LOGSTAMP"));
	}

	disable_plaintext_auth = getenv("DISABLE_PLAINTEXT_AUTH") != NULL;

	value = getenv("MAX_LOGGING_USERS");
	max_logging_users = value == NULL ? 0 : strtoul(value, NULL, 10);

	/* Initialize SSL proxy before dropping privileges so it can read
	   the certificate and private key file. */
	ssl_proxy_init();

	restrict_access_by_env();

	auth_connection_init();
	master_init();
	clients_init();

	io_imap = io_imaps = NULL;

	if (net_getsockname(LOGIN_IMAP_LISTEN_FD, NULL, NULL) == 0) {
		/* we're listening for imap */
		io_imap = io_add(LOGIN_IMAP_LISTEN_FD, IO_READ,
				 login_accept, NULL);
	}

	if (net_getsockname(LOGIN_IMAPS_LISTEN_FD, NULL, NULL) == 0) {
		/* we're listening for imaps */
		if (!ssl_initialized) {
			/* this shouldn't happen, master should have
			   disabled the imaps socket.. */
			i_fatal("BUG: SSL initialization parameters not given "
				"while they should have been");
		}

		io_imaps = io_add(LOGIN_IMAPS_LISTEN_FD, IO_READ,
				  login_accept_ssl, NULL);
	}
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	if (io_imap != NULL) io_remove(io_imap);
	if (io_imaps != NULL) io_remove(io_imaps);

	clients_deinit();
	master_deinit();
	auth_connection_deinit();

	ssl_proxy_deinit();

	closelog();
}

int main(int argc __attr_unused__, char *argv[] __attr_unused__)
{
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
