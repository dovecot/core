/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "process-title.h"
#include "fd-close-on-exec.h"
#include "auth-connection.h"
#include "master.h"
#include "client.h"
#include "ssl-proxy.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

int disable_plaintext_auth, process_per_connection, verbose_proctitle;
unsigned int max_logging_users;
unsigned int login_process_uid;

static struct ioloop *ioloop;
static struct io *io_imap, *io_imaps;
static int main_refcount;
static int closing_down;

void main_ref(void)
{
	main_refcount++;
}

void main_unref(void)
{
	if (--main_refcount == 0) {
		/* nothing to do, quit */
		io_loop_stop(ioloop);
	} else if (closing_down && clients_get_count() == 0) {
		/* last login finished, close all communications
		   to master process */
		master_close();
	}
}

void main_close_listen(void)
{
	if (closing_down)
		return;

	if (io_imap != NULL) {
		if (close(LOGIN_IMAP_LISTEN_FD) < 0)
			i_fatal("can't close() IMAP listen handle");

		io_remove(io_imap);
		io_imap = NULL;
	}

	if (io_imaps != NULL) {
		if (close(LOGIN_IMAPS_LISTEN_FD) < 0)
			i_fatal("can't close() IMAPS listen handle");

		io_remove(io_imaps);
		io_imaps = NULL;
	}

	closing_down = TRUE;
	master_notify_finished();
}

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void login_accept(void *context __attr_unused__, int listen_fd,
			 struct io *io __attr_unused__)
{
	struct ip_addr ip;
	int fd;

	fd = net_accept(listen_fd, &ip, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
		return;
	}

	if (process_per_connection)
		main_close_listen();

	(void)client_create(fd, &ip, FALSE);
}

static void login_accept_ssl(void *context __attr_unused__, int listen_fd,
			     struct io *io __attr_unused__)
{
	struct client *client;
	struct ip_addr addr;
	int fd, fd_ssl;

	fd = net_accept(listen_fd, &addr, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
		return;
	}

	if (process_per_connection)
		main_close_listen();

	fd_ssl = ssl_proxy_new(fd);
	if (fd_ssl == -1)
		net_disconnect(fd);
	else {
		client = client_create(fd_ssl, &addr, TRUE);
		client->tls = TRUE;
	}
}

static void open_logfile(void)
{
	if (getenv("IMAP_USE_SYSLOG") != NULL)
		i_set_failure_syslog("imap-login", LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(getenv("IMAP_LOGFILE"), "imap-login");
	}

	if (getenv("IMAP_INFOLOGFILE") != NULL)
		i_set_info_file(getenv("IMAP_INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("IMAP_LOGSTAMP"));
}

static void drop_privileges(void)
{
	/* Log file or syslog opening probably requires roots */
	open_logfile();

	/* Initialize SSL proxy so it can read certificate and private
	   key file. */
	ssl_proxy_init();

	/* Refuse to run as root - we should never need it and it's
	   dangerous with SSL. */
	restrict_access_by_env(TRUE);
}

static void main_init(void)
{
	const char *value;

	lib_init_signals(sig_quit);

	disable_plaintext_auth = getenv("DISABLE_PLAINTEXT_AUTH") != NULL;
	process_per_connection = getenv("PROCESS_PER_CONNECTION") != NULL;
        verbose_proctitle = getenv("VERBOSE_PROCTITLE") != NULL;

	value = getenv("MAX_LOGGING_USERS");
	max_logging_users = value == NULL ? 0 : strtoul(value, NULL, 10);

	value = getenv("PROCESS_UID");
	if (value == NULL)
		i_fatal("BUG: PROCESS_UID environment not given");
        login_process_uid = strtoul(value, NULL, 10);
	if (login_process_uid == 0)
		i_fatal("BUG: PROCESS_UID environment is 0");

        closing_down = FALSE;
	main_refcount = 0;

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

int main(int argc __attr_unused__, char *argv[], char *envp[])
{
#ifdef DEBUG
        fd_debug_verify_leaks(3, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

	process_title_init(argv, envp);
	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
