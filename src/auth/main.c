/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "child-wait.h"
#include "sql-api.h"
#include "module-dir.h"
#include "randgen.h"
#include "password-scheme.h"
#include "mech.h"
#include "auth.h"
#include "auth-request-handler.h"
#include "auth-worker-server.h"
#include "auth-worker-client.h"
#include "auth-master-interface.h"
#include "auth-master-listener.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

struct ioloop *ioloop;
bool standalone = FALSE, worker = FALSE, shutdown_request = FALSE;
time_t process_start_time;

static struct module *modules = NULL;
static struct auth *auth;
static struct auth_worker_client *worker_client;

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (si->si_signo != SIGINT) {
		i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
			  si->si_signo, dec2str(si->si_pid),
			  dec2str(si->si_uid),
			  lib_signal_code_to_str(si->si_signo, si->si_code));
	}
	io_loop_stop(ioloop);
}

static void open_logfile(void)
{
	const char *env;

	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

	if (getenv("USE_SYSLOG") != NULL) {
		env = getenv("SYSLOG_FACILITY");
		i_set_failure_syslog("dovecot-auth", LOG_NDELAY,
				     env == NULL ? LOG_MAIL : atoi(env));
	} else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), "dovecot-auth: ");
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static uid_t get_uid(const char *user)
{
	struct passwd *pw;

	if (*user == '\0')
		return (uid_t)-1;
	if (is_numeric(user, '\0'))
		return strtoul(user, NULL, 10);

	errno = 0;
	if ((pw = getpwnam(user)) == NULL) {
		if (errno != 0)
			i_fatal("User '%s' lookup failed: %m", user);
		setpwent();
		if (getpwent() == NULL) {
			if (errno != 0)
				i_fatal("getpwent() failed: %m");
			i_fatal("getpwnam() failed for some reason. "
				"Is auth_process_size set to too low?");
		}
		i_fatal("User doesn't exist: %s", user);
	}
	return pw->pw_uid;
}

static gid_t get_gid(const char *group)
{
	struct group *gr;

	if (*group == '\0')
		return (gid_t)-1;
	if (is_numeric(group, '\0'))
		return strtoul(group, NULL, 10);

	errno = 0;
	if ((gr = getgrnam(group)) == NULL) {
		if (errno != 0)
			i_fatal("Group '%s' lookup failed: %m", group);
		else
			i_fatal("Group doesn't exist: %s", group);
	}
	return gr->gr_gid;
}

static int create_unix_listener(const struct auth_socket_unix_settings *set,
				int backlog)
{
	mode_t old_umask;
	uid_t uid;
	gid_t gid;
	int fd;

	old_umask = umask((set->mode ^ 0777) & 0777);
	fd = net_listen_unix_unlink_stale(set->path, backlog);
	umask(old_umask);
	if (fd == -1) {
		if (errno == EADDRINUSE)
			i_fatal("Socket already exists: %s", set->path);
		else
			i_fatal("net_listen_unix(%s) failed: %m", set->path);
	}

	uid = get_uid(set->user); gid = get_gid(set->group);
	if (chown(set->path, uid, gid) < 0) {
		i_fatal("chown(%s, %s(%s), %s(%s)) failed: %m",
			set->path, dec2str(uid), set->user,
			dec2str(gid), set->group);
	}
	return fd;
}

static void
add_extra_unix_listeners(struct auth_master_listener *listener,
			 struct auth_socket_unix_settings *const *sets,
			 unsigned int count, enum listener_type type)
{
	unsigned int i;
	int fd;

	for (i = 0; i < count; i++) {
		fd = create_unix_listener(sets[i], 128);
		auth_master_listener_add(listener, fd, sets[i]->path, type);
	}
}

static void add_extra_listeners(struct auth *auth)
{
	struct auth_master_listener *listener;
	struct auth_socket_settings *const *sockets;
	struct auth_socket_unix_settings *const *unix_sockets;
	unsigned int i, count, count2;

	if (!array_is_created(&auth->set->sockets))
		return;

	sockets = array_get(&auth->set->sockets, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(sockets[i]->type, "listen") != 0)
			continue;

		listener = auth_master_listener_create(auth);

		if (array_is_created(&sockets[i]->masters)) {
			unix_sockets = array_get(&sockets[i]->masters, &count2);
			add_extra_unix_listeners(listener, unix_sockets, count2,
						 LISTENER_MASTER);
		}
		if (array_is_created(&sockets[i]->clients)) {
			unix_sockets = array_get(&sockets[i]->clients, &count2);
			add_extra_unix_listeners(listener, unix_sockets, count2,
						 LISTENER_CLIENT);
		}
	}
}

static void drop_privileges(void)
{
	const char *version, *name;

	version = getenv("DOVECOT_VERSION");
	if (version != NULL && strcmp(version, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, dovecot-auth is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", version);
	}

	standalone = getenv("DOVECOT_MASTER") == NULL;
	if (standalone && getenv("AUTH_1") == NULL) {
		i_fatal("dovecot-auth is usually started through "
			"dovecot master process. If you wish to run "
			"it standalone, you'll need to set AUTH_* "
			"environment variables (AUTH_1 isn't set).");
	}
	name = getenv("AUTH_NAME");
	if (name == NULL)
		i_fatal("Missing AUTH_NAME environment");

	open_logfile();

	/* Open /dev/urandom before chrooting */
	random_init();

	/* Load built-in SQL drivers (if any) */
	sql_drivers_init();
	sql_drivers_register_all();

	/* Initialize databases so their configuration files can be readable
	   only by root. Also load all modules here. */
	passdbs_init();
	userdbs_init();
	modules = module_dir_load(AUTH_MODULE_DIR, NULL, TRUE, version);
	module_dir_init(modules);
	auth = auth_preinit(auth_settings_read(name));
	auth_master_listeners_init();
	if (!worker)
		add_extra_listeners(auth);

	/* Password lookups etc. may require roots, allow it. */
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(bool nodaemon)
{
	struct auth_master_listener *listener;

        process_start_time = ioloop_time;

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);

	/* If auth caches aren't used, just ignore these signals */
	lib_signals_ignore(SIGHUP, TRUE);
	lib_signals_ignore(SIGUSR2, TRUE);

	child_wait_init();
	mech_init(auth->set);
	password_schemes_init();
	auth_init(auth);
	auth_request_handler_init();

	if (worker) {
		worker_client =
			auth_worker_client_create(auth, WORKER_SERVER_FD);
		return;
	}

	if (getenv("DOVECOT_MASTER") == NULL) {
		/* starting standalone */
		if (!nodaemon) {
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
		}
	} else {
		listener = auth_master_listener_create(auth);
		(void)auth_master_connection_create(listener, MASTER_SOCKET_FD);
		auth_master_listener_add(listener, CLIENT_LISTEN_FD,
					 NULL, LISTENER_CLIENT);
	}

	/* everything initialized, notify masters that all is well */
	auth_master_listeners_send_handshake();
}

static void main_deinit(void)
{
	if (worker_client != NULL)
		auth_worker_client_unref(&worker_client);
	else
		auth_request_handler_flush_failures(TRUE);

        auth_worker_server_deinit();
	auth_master_listeners_deinit();

	module_dir_unload(&modules);
	userdbs_deinit();
	passdbs_deinit();
	mech_deinit(auth->set);
	auth_deinit(&auth);

        password_schemes_deinit();
	sql_drivers_deinit();
	random_deinit();

	child_wait_deinit();
	lib_signals_deinit();
	closelog();
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	bool foreground = FALSE;

#ifdef DEBUG
	if (getenv("GDB") == NULL)
		fd_debug_verify_leaks(WORKER_SERVER_FD + 1, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	ioloop = io_loop_create();

	while (argv[1] != NULL) {
		if (strcmp(argv[1], "-F") == 0)
			foreground = TRUE;
		else if (strcmp(argv[1], "-w") == 0)
			worker = TRUE;
		argv++;
	}

	T_BEGIN {
		drop_privileges();
		main_init(foreground);
	} T_END;
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

        return 0;
}
