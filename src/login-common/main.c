/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "process-title.h"
#include "fd-close-on-exec.h"
#include "auth-connection.h"
#include "master.h"
#include "client-common.h"
#include "ssl-proxy.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

int disable_plaintext_auth, process_per_connection, verbose_proctitle;
int verbose_ssl;
unsigned int max_logging_users;
unsigned int login_process_uid;

static struct ioloop *ioloop;
static struct io *io_listen, *io_ssl_listen;
static int main_refcount;
static int is_inetd, closing_down;

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

	if (io_listen != NULL) {
		if (close(LOGIN_LISTEN_FD) < 0)
			i_fatal("close(listen) failed: %m");

		io_remove(io_listen);
		io_listen = NULL;
	}

	if (io_ssl_listen != NULL) {
		if (close(LOGIN_SSL_LISTEN_FD) < 0)
			i_fatal("close(ssl_listen) failed: %m");

		io_remove(io_ssl_listen);
		io_ssl_listen = NULL;
	}

	closing_down = TRUE;
	master_notify_finished();
}

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void login_accept(void *context __attr_unused__)
{
	struct ip_addr ip;
	int fd;

	fd = net_accept(LOGIN_LISTEN_FD, &ip, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
		return;
	}

	if (process_per_connection)
		main_close_listen();

	(void)client_create(fd, &ip, FALSE);
}

static void login_accept_ssl(void *context __attr_unused__)
{
	struct ip_addr ip;
	int fd, fd_ssl;

	fd = net_accept(LOGIN_SSL_LISTEN_FD, &ip, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
		return;
	}

	if (process_per_connection)
		main_close_listen();

	fd_ssl = ssl_proxy_new(fd, &ip);
	if (fd_ssl == -1)
		net_disconnect(fd);
	else
		(void)client_create(fd_ssl, &ip, TRUE);
}

static void open_logfile(const char *name)
{
	if (getenv("USE_SYSLOG") != NULL)
		i_set_failure_syslog(name, LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), name);
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static void drop_privileges(const char *name)
{
	/* Log file or syslog opening probably requires roots */
	open_logfile(name);

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
        verbose_ssl = getenv("VERBOSE_SSL") != NULL;

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
	clients_init();

	io_listen = io_ssl_listen = NULL;

	if (!is_inetd) {
		if (net_getsockname(LOGIN_LISTEN_FD, NULL, NULL) == 0) {
			io_listen = io_add(LOGIN_LISTEN_FD, IO_READ,
					   login_accept, NULL);
		}

		if (net_getsockname(LOGIN_SSL_LISTEN_FD, NULL, NULL) == 0) {
			if (!ssl_initialized) {
				/* this shouldn't happen, master should have
				   disabled the ssl socket.. */
				i_fatal("BUG: SSL initialization parameters "
					"not given while they should have "
					"been");
			}

			io_ssl_listen = io_add(LOGIN_SSL_LISTEN_FD, IO_READ,
					       login_accept_ssl, NULL);
		}

		/* initialize master last - it sends the "we're ok"
		   notification */
		master_init(LOGIN_MASTER_SOCKET_FD, TRUE);
	}
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	if (io_listen != NULL) io_remove(io_listen);
	if (io_ssl_listen != NULL) io_remove(io_ssl_listen);

	ssl_proxy_deinit();

	auth_connection_deinit();
	clients_deinit();
	master_deinit();

	closelog();
}

int main(int argc __attr_unused__, char *argv[], char *envp[])
{
	const char *name, *group_name;
	struct ip_addr ip;
	int i, fd = -1, master_fd = -1;

	is_inetd = getenv("DOVECOT_MASTER") == NULL;

#ifdef DEBUG
	if (!is_inetd)
		fd_debug_verify_leaks(4, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();

	if (is_inetd) {
		/* running from inetd. create master process before
		   dropping privileges. */
		group_name = strrchr(argv[0], '/');
		group_name = group_name == NULL ? argv[0] : group_name+1;
		group_name = t_strcut(group_name, '-');

		for (i = 1; i < argc; i++) {
			if (strncmp(argv[i], "--group=", 8) == 0) {
				group_name = argv[1]+8;
				break;
			}
		}

		master_fd = master_connect(group_name);
	}

	name = strrchr(argv[0], '/');
	drop_privileges(name == NULL ? argv[0] : name+1);

	process_title_init(argv, envp);
	ioloop = io_loop_create(system_pool);
	main_init();

	if (is_inetd) {
		if (net_getsockname(1, &ip, NULL) < 0) {
			i_fatal("%s can be started only through dovecot "
				"master process, inetd or equilevant", argv[0]);
		}

		fd = 1;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--ssl") == 0) {
				fd = ssl_proxy_new(fd, &ip);
				if (fd == -1)
					i_fatal("SSL initialization failed");
			} else if (strncmp(argv[i], "--group=", 8) != 0)
				i_fatal("Unknown parameter: %s", argv[i]);
		}

		master_init(master_fd, FALSE);
		closing_down = TRUE;
	}

	if (fd != -1)
		(void)client_create(fd, &ip, TRUE);

	io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
