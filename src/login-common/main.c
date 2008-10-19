/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "array.h"
#include "lib-signals.h"
#include "randgen.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "process-title.h"
#include "fd-close-on-exec.h"
#include "master.h"
#include "client-common.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "login-proxy.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

bool disable_plaintext_auth, process_per_connection;
bool verbose_proctitle, verbose_ssl, verbose_auth;
bool ssl_require_client_cert;
const char *greeting, *log_format;
const char *const *log_format_elements;
const char *trusted_networks;
unsigned int max_connections;
unsigned int login_process_uid;
struct auth_client *auth_client;
bool closing_down;

static const char *process_name;
static struct ioloop *ioloop;
static int main_refcount;
static bool is_inetd, listening;

static ARRAY_DEFINE(listen_ios, struct io *);
static unsigned int listen_count, ssl_listen_count;

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
		/* we might still be proxying. close the connection to
		   dovecot-auth, since it's not needed anymore. */
		if (auth_client != NULL)
			auth_client_free(&auth_client);
	} else if (clients_get_count() == 0) {
		/* make sure we clear all the memory used by the
		   authentication connections. also this makes sure that if
		   this connection's authentication was finished but the master
		   login wasn't, the next connection won't be able to log in
		   as this user by finishing the master login. */
		if (auth_client != NULL)
			auth_client_reconnect(auth_client);
	}
}

static void sig_die(int signo, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static void login_accept(void *context)
{
	int listen_fd = POINTER_CAST_TO(context, int);
	struct ip_addr remote_ip, local_ip;
	unsigned int remote_port, local_port;
	struct client *client;
	int fd;

	fd = net_accept(listen_fd, &remote_ip, &remote_port);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept() failed: %m");
		return;
	}

	if (net_getsockname(fd, &local_ip, &local_port) < 0) {
		memset(&local_ip, 0, sizeof(local_ip));
		local_port = 0;
	}

	client = client_create(fd, FALSE, &local_ip, &remote_ip);
	client->remote_port = remote_port;
	client->local_port = local_port;

	if (process_per_connection) {
		closing_down = TRUE;
		main_listen_stop();
	}
}

static void login_accept_ssl(void *context)
{
	int listen_fd = POINTER_CAST_TO(context, int);
	struct ip_addr remote_ip, local_ip;
	unsigned int remote_port, local_port;
	struct client *client;
	struct ssl_proxy *proxy;
	int fd, fd_ssl;

	fd = net_accept(listen_fd, &remote_ip, &remote_port);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept() failed: %m");
		return;
	}

	if (net_getsockname(fd, &local_ip, &local_port) < 0) {
		memset(&local_ip, 0, sizeof(local_ip));
		local_port = 0;
	}

	fd_ssl = ssl_proxy_new(fd, &remote_ip, &proxy);
	if (fd_ssl == -1)
		net_disconnect(fd);
	else {
		client = client_create(fd_ssl, TRUE, &local_ip, &remote_ip);
		client->proxy = proxy;
		client->remote_port = remote_port;
		client->local_port = local_port;
	}

	if (process_per_connection) {
		closing_down = TRUE;
		main_listen_stop();
	}
}

void main_listen_start(void)
{
	struct io *io;
	unsigned int i, current_count;
	int cur_fd;

	if (listening)
		return;
	if (closing_down) {
		/* typically happens only with
		   login_process_per_connection=yes after client logs in */
		master_notify_state_change(LOGIN_STATE_FULL_LOGINS);
		return;
	}

	current_count = ssl_proxy_get_count() + login_proxy_get_count();
	if (current_count >= max_connections) {
		/* can't accept any more connections until existing proxies
		   get destroyed */
		return;
	}

	cur_fd = LOGIN_MASTER_SOCKET_FD + 1;
	i_array_init(&listen_ios, listen_count + ssl_listen_count);
	for (i = 0; i < listen_count; i++, cur_fd++) {
		io = io_add(cur_fd, IO_READ, login_accept,
			    POINTER_CAST(cur_fd));
		array_append(&listen_ios, &io, 1);
	}
	for (i = 0; i < ssl_listen_count; i++, cur_fd++) {
		io = io_add(cur_fd, IO_READ, login_accept_ssl,
			    POINTER_CAST(cur_fd));
		array_append(&listen_ios, &io, 1);
	}
	listening = TRUE;

	/* the initial notification tells master that we're ok. if we die
	   before sending it, the master should shutdown itself. */
	master_notify_state_change(LOGIN_STATE_LISTENING);
}

void main_listen_stop(void)
{
	struct io **ios;
	unsigned int i, count;
	int cur_fd;

	if (!listening)
		return;

	ios = array_get_modifiable(&listen_ios, &count);
	for (i = 0; i < count; i++)
		io_remove(&ios[i]);
	array_free(&listen_ios);

	if (closing_down) {
		cur_fd = LOGIN_MASTER_SOCKET_FD + 1;
		for (i = 0; i < count; i++, cur_fd++) {
			if (close(cur_fd) < 0) {
				i_fatal("close(listener %d) failed: %m",
					cur_fd);
			}
		}
	}

	listening = FALSE;
	if (io_loop_is_running(ioloop)) {
		master_notify_state_change(clients_get_count() == 0 ?
					   LOGIN_STATE_FULL_LOGINS :
					   LOGIN_STATE_FULL_PRELOGINS);
	}
}

void connection_queue_add(unsigned int connection_count)
{
	unsigned int current_count;

	if (process_per_connection)
		return;

	current_count = clients_get_count() + ssl_proxy_get_count() +
		login_proxy_get_count();
	if (current_count + connection_count + 2 >= max_connections) {
		/* after this client we've reached max users count,
		   so stop listening for more. reserve +2 extra for SSL with
		   login proxy connections. */
		main_listen_stop();

		if (current_count >= max_connections) {
			/* already reached max. users count, kill few of the
			   oldest connections.

			   this happens when we've maxed out the login process
			   count and master has told us to start listening for
			   new connections even though we're full. */
			client_destroy_oldest();
		}
	}
}

static void auth_connect_notify(struct auth_client *client ATTR_UNUSED,
				bool connected, void *context ATTR_UNUSED)
{
	if (connected)
                clients_notify_auth_connected();
}

static void drop_privileges(void)
{
	const char *value;

	if (!is_inetd)
		i_set_failure_internal();
	else {
		/* log to syslog */
		value = getenv("SYSLOG_FACILITY");
		i_set_failure_syslog(process_name, LOG_NDELAY,
				     value == NULL ? LOG_MAIL : atoi(value));

		/* if we don't chroot, we must chdir */
		value = getenv("LOGIN_DIR");
		if (value != NULL) {
			if (chdir(value) < 0)
				i_error("chdir(%s) failed: %m", value);
		}
	}

	/* Initialize SSL proxy so it can read certificate and private
	   key file. */
	random_init();
	ssl_proxy_init();

	value = getenv("LISTEN_FDS");
	listen_count = value == NULL ? 0 : atoi(value);
	value = getenv("SSL_LISTEN_FDS");
	ssl_listen_count = value == NULL ? 0 : atoi(value);
	value = getenv("MAX_CONNECTIONS");
	max_connections = value == NULL ? 1 : strtoul(value, NULL, 10);

	/* set the number of fds we want to use. it may get increased or
	   decreased. leave a couple of extra fds for auth sockets and such.
	   normal connections each use one fd, but SSL connections use two */
	restrict_fd_limit(LOGIN_MASTER_SOCKET_FD + 16 +
			  listen_count + ssl_listen_count +
			  max_connections*2);

	/* Refuse to run as root - we should never need it and it's
	   dangerous with SSL. */
	restrict_access_by_env(TRUE);

	/* make sure we can't fork() */
	restrict_process_size((unsigned int)-1, 1);
}

static void main_init(void)
{
	const char *value;

	value = getenv("DOVECOT_VERSION");
	if (value != NULL && strcmp(value, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, login is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", value);
	}

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);

	disable_plaintext_auth = getenv("DISABLE_PLAINTEXT_AUTH") != NULL;
	process_per_connection = getenv("PROCESS_PER_CONNECTION") != NULL;
	verbose_proctitle = getenv("VERBOSE_PROCTITLE") != NULL;
        verbose_ssl = getenv("VERBOSE_SSL") != NULL;
        verbose_auth = getenv("VERBOSE_AUTH") != NULL;
	ssl_require_client_cert = getenv("SSL_REQUIRE_CLIENT_CERT") != NULL;

	greeting = getenv("GREETING");
	if (greeting == NULL)
		greeting = PACKAGE" ready.";

	value = getenv("LOG_FORMAT_ELEMENTS");
	if (value == NULL)
		value = "user=<%u> method=%m rip=%r lip=%l %c : %$";
	log_format_elements = t_strsplit(value, " ");

	log_format = getenv("LOG_FORMAT");
	if (log_format == NULL)
		log_format = "%$: %s";

	trusted_networks = getenv("TRUSTED_NETWORKS");

	value = getenv("PROCESS_UID");
	if (value == NULL)
		i_fatal("BUG: PROCESS_UID environment not given");
        login_process_uid = strtoul(value, NULL, 10);
	if (login_process_uid == 0)
		i_fatal("BUG: PROCESS_UID environment is 0");

	/* capability default is set in imap/pop3-login */
	value = getenv("CAPABILITY_STRING");
	if (value != NULL && *value != '\0')
		capability_string = value;

        closing_down = FALSE;
	main_refcount = 0;

	auth_client = auth_client_new(login_process_uid);
        auth_client_set_connect_notify(auth_client, auth_connect_notify, NULL);
	clients_init();

	if (!ssl_initialized && ssl_listen_count > 0) {
		/* this shouldn't happen, master should have
		   disabled the ssl socket.. */
		i_fatal("BUG: SSL initialization parameters not given "
			"while they should have been");
	}

	if (!is_inetd) {
		master_init(LOGIN_MASTER_SOCKET_FD);
		main_listen_start();
	}
}

static void main_deinit(void)
{
	closing_down = TRUE;
	main_listen_stop();

	ssl_proxy_deinit();
	login_proxy_deinit();

	if (auth_client != NULL)
		auth_client_free(&auth_client);
	clients_deinit();
	master_deinit();

	lib_signals_deinit();
	closelog();
}

int main(int argc ATTR_UNUSED, char *argv[], char *envp[])
{
	const char *group_name;
	struct ip_addr remote_ip, local_ip;
	unsigned int remote_port, local_port;
	struct ssl_proxy *proxy = NULL;
	struct client *client;
	int i, fd = -1, master_fd = -1;
	bool ssl = FALSE;

	is_inetd = getenv("DOVECOT_MASTER") == NULL;

#ifdef DEBUG
	if (!is_inetd && getenv("GDB") == NULL) {
		const char *env;

		i = LOGIN_MASTER_SOCKET_FD + 1;
		env = getenv("LISTEN_FDS");
		if (env != NULL) i += atoi(env);
		env = getenv("SSL_LISTEN_FDS");
		if (env != NULL) i += atoi(env);

		fd_debug_verify_leaks(i, 1024);
	}
#endif
	/* clear all allocated memory before freeing it. this makes the login
	   processes pretty safe to reuse for new connections since the
	   attacker won't be able to find anything interesting from the
	   memory. */
	default_pool = system_clean_pool;
	data_stack_set_clean_after_pop(TRUE);

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();

	if (is_inetd) {
		/* running from inetd. create master process before
		   dropping privileges. */
		process_name = strrchr(argv[0], '/');
		process_name = process_name == NULL ? argv[0] : process_name+1;
		group_name = t_strcut(process_name, '-');

		for (i = 1; i < argc; i++) {
			if (strncmp(argv[i], "--group=", 8) == 0) {
				group_name = argv[1]+8;
				break;
			}
		}

		master_fd = master_connect(group_name);
	}

	drop_privileges();

	process_title_init(argv, envp);
	ioloop = io_loop_create();
	main_init();

	if (is_inetd) {
		if (net_getpeername(1, &remote_ip, &remote_port) < 0) {
			i_fatal("%s can be started only through dovecot "
				"master process, inetd or equivalent", argv[0]);
		}
		if (net_getsockname(1, &local_ip, &local_port) < 0) {
			memset(&local_ip, 0, sizeof(local_ip));
			local_port = 0;
		}

		fd = 1;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--ssl") == 0)
				ssl = TRUE;
			else if (strncmp(argv[i], "--group=", 8) != 0)
				i_fatal("Unknown parameter: %s", argv[i]);
		}

		/* hardcoded imaps and pop3s ports to be SSL by default */
		if (local_port == 993 || local_port == 995 || ssl) {
			ssl = TRUE;
			fd = ssl_proxy_new(fd, &remote_ip, &proxy);
			if (fd == -1)
				return 1;
		}

		master_init(master_fd);
		closing_down = TRUE;

		if (fd != -1) {
			client = client_create(fd, ssl, &local_ip, &remote_ip);
			client->proxy = proxy;
			client->remote_port = remote_port;
			client->local_port = local_port;
		}
	}

	io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

        return 0;
}
