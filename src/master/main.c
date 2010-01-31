/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "fd-close-on-exec.h"
#include "array.h"
#include "write-full.h"
#include "env-util.h"
#include "hostpid.h"
#include "abspath.h"
#include "restrict-process-size.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "askpass.h"
#include "capabilities.h"
#include "service.h"
#include "service-anvil.h"
#include "service-listen.h"
#include "service-monitor.h"
#include "service-process.h"
#include "service-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#define DOVECOT_CONFIG_BIN_PATH BINDIR"/doveconf"

#define MASTER_SERVICE_NAME "master"
#define FATAL_FILENAME "master-fatal.lastlog"
#define MASTER_PID_FILE_NAME "master.pid"
#define SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_SECS (60*3)

uid_t master_uid;
gid_t master_gid;
bool core_dumps_disabled;
char ssl_manual_key_password[100];
int null_fd;
struct service_list *services;

static char *pidfile_path;
static fatal_failure_callback_t *orig_fatal_callback;
static failure_callback_t *orig_error_callback;
static const char *child_process_env[3]; /* @UNSAFE */

static const struct setting_parser_info *set_roots[] = {
	&master_setting_parser_info,
	NULL
};

void process_exec(const char *cmd, const char *extra_args[])
{
	const char *executable, *p, **argv;

	argv = t_strsplit(cmd, " ");
	executable = argv[0];

	if (extra_args != NULL) {
		unsigned int count1, count2;
		const char **new_argv;

		/* @UNSAFE */
		count1 = str_array_length(argv);
		count2 = str_array_length(extra_args);
		new_argv = t_new(const char *, count1 + count2 + 1);
		memcpy(new_argv, argv, sizeof(const char *) * count1);
		memcpy(new_argv + count1, extra_args,
		       sizeof(const char *) * count2);
		argv = new_argv;
	}

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	/* prefix with dovecot/ */
	argv[0] = t_strconcat(PACKAGE"/", argv[0], NULL);

	(void)execv(executable, (char **)argv);
	i_fatal_status(errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		       "execv(%s) failed: %m", executable);
}

int get_uidgid(const char *user, uid_t *uid_r, gid_t *gid_r,
	       const char **error_r)
{
	struct passwd *pw;

	if (*user == '\0') {
		*uid_r = (uid_t)-1;
		*gid_r = (gid_t)-1;
		return 0;
	}

	if ((pw = getpwnam(user)) == NULL) {
		*error_r = t_strdup_printf("User doesn't exist: %s", user);
		return -1;
	}

	*uid_r = pw->pw_uid;
	*gid_r = pw->pw_gid;
	return 0;
}

int get_gid(const char *group, gid_t *gid_r, const char **error_r)
{
	struct group *gr;

	if (*group == '\0') {
		*gid_r = (gid_t)-1;
		return 0;
	}

	if ((gr = getgrnam(group)) == NULL) {
		*error_r = t_strdup_printf("Group doesn't exist: %s", group);
		return -1;
	}

	*gid_r = gr->gr_gid;
	return 0;
}

static void ATTR_NORETURN ATTR_FORMAT(3, 0)
master_fatal_callback(enum log_type type, int status,
		      const char *format, va_list args)
{
	const char *path, *str;
	va_list args2;
	int fd;

	/* if we already forked a child process, this isn't fatal for the
	   main process and there's no need to write the fatal file. */
	if (getpid() == strtol(my_pid, NULL, 10)) {
		/* write the error message to a file (we're chdired to
		   base dir) */
		path = t_strconcat(FATAL_FILENAME, NULL);
		fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if (fd != -1) {
			VA_COPY(args2, args);
			str = t_strdup_vprintf(format, args2);
			write_full(fd, str, strlen(str));
			(void)close(fd);
		}
	}

	orig_fatal_callback(type, status, format, args);
	abort(); /* just to silence the noreturn attribute warnings */
}

static void ATTR_NORETURN
startup_fatal_handler(enum log_type type, int status,
		      const char *fmt, va_list args)
{
	va_list args2;

	VA_COPY(args2, args);
	fprintf(stderr, "%s%s\n", failure_log_type_prefixes[type],
		t_strdup_vprintf(fmt, args2));
	orig_fatal_callback(type, status, fmt, args);
	abort();
}

static void
startup_error_handler(enum log_type type, const char *fmt, va_list args)
{
	va_list args2;

	VA_COPY(args2, args);
	fprintf(stderr, "%s%s\n", failure_log_type_prefixes[type],
		t_strdup_vprintf(fmt, args2));
	orig_error_callback(type, fmt, args);
}

static void fatal_log_check(const struct master_settings *set)
{
	const char *path;
	char buf[1024];
	ssize_t ret;
	int fd;

	path = t_strconcat(set->base_dir, "/"FATAL_FILENAME, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return;

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		i_error("read(%s) failed: %m", path);
	else {
		buf[ret] = '\0';
		fprintf(stderr, "Last died with error (see error log for more "
			"information): %s\n", buf);
	}

	close(fd);
	if (unlink(path) < 0)
		i_error("unlink(%s) failed: %m", path);
}

static bool pid_file_read(const char *path, pid_t *pid_r)
{
	char buf[32];
	int fd;
	ssize_t ret;
	bool found;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return FALSE;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret == 0)
			i_error("Empty PID file in %s, overriding", path);
		else
			i_fatal("read(%s) failed: %m", path);
		found = FALSE;
	} else {
		if (buf[ret-1] == '\n')
			ret--;
		buf[ret] = '\0';
		*pid_r = atoi(buf);

		found = !(*pid_r == getpid() ||
			  (kill(*pid_r, 0) < 0 && errno == ESRCH));
	}
	(void)close(fd);
	return found;
}

static void pid_file_check_running(const char *path)
{
	pid_t pid;

	if (!pid_file_read(path, &pid))
		return;

	i_fatal("Dovecot is already running with PID %s "
		"(read from %s)", dec2str(pid), path);
}

static void send_master_signal(int signo)
{
	pid_t pid;

	if (!pid_file_read(pidfile_path, &pid)) {
		i_fatal("Dovecot is not running (read from %s)", pidfile_path);
		return;
	}

	if (kill(pid, signo) < 0)
		i_fatal("kill(%s, %d) failed: %m", dec2str(pid), signo);
	exit(0);
}

static void create_pid_file(const char *path)
{
	const char *pid;
	int fd;

	pid = t_strconcat(dec2str(getpid()), "\n", NULL);

	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write_full(fd, pid, strlen(pid)) < 0)
		i_fatal("write() failed in %s: %m", path);
	(void)close(fd);
}

static void create_config_symlink(const struct master_settings *set)
{
	const char *base_config_path;

	base_config_path = t_strconcat(set->base_dir, "/"PACKAGE".conf", NULL);
	if (unlink(base_config_path) < 0 && errno != ENOENT)
		i_error("unlink(%s) failed: %m", base_config_path);

	if (symlink(services->config->config_file_path, base_config_path) < 0) {
		i_error("symlink(%s, %s) failed: %m",
			services->config->config_file_path, base_config_path);
	}
}

static void
sig_settings_reload(const siginfo_t *si ATTR_UNUSED,
		    void *context ATTR_UNUSED)
{
	struct master_service_settings_input input;
	const struct master_settings *set;
	void **sets;
	struct service_list *new_services;
	struct service *service;
	const char *error;

	i_warning("SIGHUP received - reloading configuration");

	/* see if hostname changed */
	hostpid_init();

	if (services->config->process_avail == 0) {
		/* we can't reload config if there's no config process. */
		if (service_process_create(services->config) == NULL) {
			i_error("Can't reload configuration because "
				"we couldn't create a config process");
			return;
		}
	}

	memset(&input, 0, sizeof(input));
	input.roots = set_roots;
	input.module = MASTER_SERVICE_NAME;
	input.config_path = services_get_config_socket_path(services);
	if (master_service_settings_read(master_service, &input, &error) < 0) {
		i_error("Error reading configuration: %s", error);
		return;
	}
	sets = master_service_settings_get_others(master_service);
	set = sets[0];

	if (services_create(set, child_process_env,
			    &new_services, &error) < 0) {
		/* new configuration is invalid, keep the old */
		i_error("Config reload failed: %s", error);
		return;
	}
	new_services->config->config_file_path =
		p_strdup(new_services->pool,
			 services->config->config_file_path);

	/* switch to new configuration. */
	services_monitor_stop(services);
	if (services_listen_using(new_services, services) < 0) {
		services_monitor_start(services);
		return;
	}

	/* anvil never dies. it just gets moved to the new services list */
	service = service_lookup_type(services, SERVICE_TYPE_ANVIL);
	if (service != NULL) {
		while (service->processes != NULL)
			service_process_destroy(service->processes);
	}
	services_destroy(services);

	services = new_services;
        services_monitor_start(services);
}

static void
sig_log_reopen(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
        service_signal(services->log, SIGUSR1);

	master_service_init_log(master_service, "master: ");
	i_set_fatal_handler(master_fatal_callback);
}

static void
sig_reap_children(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	services_monitor_reap_children();
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
		  si->si_signo, dec2str(si->si_pid),
		  dec2str(si->si_uid),
		  lib_signal_code_to_str(si->si_signo, si->si_code));
	master_service_stop(master_service);
}

static void main_log_startup(void)
{
#define STARTUP_STRING PACKAGE_NAME" v"VERSION" starting up"
	rlim_t core_limit;

	core_dumps_disabled = restrict_get_core_limit(&core_limit) == 0 &&
		core_limit == 0;
	if (core_dumps_disabled)
		i_info(STARTUP_STRING" (core dumps disabled)");
	else
		i_info(STARTUP_STRING);
}

static void main_init(const struct master_settings *set, bool log_error)
{
	drop_capabilities();

	/* deny file access from everyone else except owner */
        (void)umask(0077);

	if (log_error) {
		fprintf(stderr, "Writing to error logs and killing myself..\n");
		i_debug("This is Dovecot's debug log");
		i_info("This is Dovecot's info log");
		i_warning("This is Dovecot's warning log");
		i_error("This is Dovecot's error log");
		i_fatal("This is Dovecot's fatal log");
	}
	main_log_startup();

	lib_signals_init();
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
        lib_signals_set_handler(SIGHUP, TRUE, sig_settings_reload, NULL);
        lib_signals_set_handler(SIGUSR1, TRUE, sig_log_reopen, NULL);
        lib_signals_set_handler(SIGCHLD, TRUE, sig_reap_children, NULL);
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);

	create_pid_file(pidfile_path);
	create_config_symlink(set);

	services_monitor_start(services);
}

static void main_deinit(void)
{
	if (unlink(pidfile_path) < 0)
		i_error("unlink(%s) failed: %m", pidfile_path);
	i_free(pidfile_path);

	services_destroy(services);
	service_anvil_global_deinit();
	service_pids_deinit();
}

static const char *get_full_config_path(struct service_list *list)
{
	const char *path;

	path = master_service_get_config_path(master_service);
	if (*path == '/')
		return path;

	return p_strdup(list->pool, t_abspath(path));
}

static void master_time_moved(time_t old_time, time_t new_time)
{
	unsigned long secs;

	if (new_time >= old_time)
		return;

	/* time moved backwards. disable launching new service processes
	   until  */
	secs = old_time - new_time + 1;
	if (secs > SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_SECS)
		secs = SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_SECS;
	services_throttle_time_sensitives(services, secs);
	i_warning("Time moved backwards by %lu seconds, "
		  "waiting for %lu secs until new services are launched again.",
		  (unsigned long)(old_time - new_time), secs);
}

static void daemonize(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		i_fatal("fork() failed: %m");

	if (pid != 0)
		_exit(0);

	if (setsid() < 0)
		i_fatal("setsid() failed: %m");

	/* update my_pid */
	hostpid_init();
}

static void print_help(void)
{
	fprintf(stderr,
"Usage: dovecot [-F] [-c <config file>] [-p] [-n] [-a] [--help] [--version]\n"
"       [--build-options] [--log-error] [reload] [stop]\n");
}

static void print_build_options(void)
{
	printf("Build options:"
#ifdef IOLOOP_EPOLL
		" ioloop=epoll"
#endif
#ifdef IOLOOP_KQUEUE
		" ioloop=kqueue"
#endif
#ifdef IOLOOP_POLL
		" ioloop=poll"
#endif
#ifdef IOLOOP_SELECT
		" ioloop=select"
#endif
#ifdef IOLOOP_NOTIFY_DNOTIFY
		" notify=dnotify"
#endif
#ifdef IOLOOP_NOTIFY_INOTIFY
		" notify=inotify"
#endif
#ifdef IOLOOP_NOTIFY_KQUEUE
		" notify=kqueue"
#endif
#ifdef HAVE_IPV6
		" ipv6"
#endif
#ifdef HAVE_GNUTLS
		" gnutls"
#endif
#ifdef HAVE_OPENSSL
		" openssl"
#endif
	"\nMail storages: "MAIL_STORAGES"\n"
#ifdef SQL_DRIVER_PLUGINS
	"SQL driver plugins:"
#else
	"SQL drivers:"
#endif
#ifdef BUILD_MYSQL
		" mysql"
#endif
#ifdef BUILD_PGSQL
		" postgresql"
#endif
#ifdef BUILD_SQLITE
		" sqlite"
#endif
	"\nPassdb:"
#ifdef PASSDB_BSDAUTH
		" bsdauth"
#endif
#ifdef PASSDB_CHECKPASSWORD
		" checkpassword"
#endif
#ifdef PASSDB_LDAP
		" ldap"
#endif
#ifdef PASSDB_PAM
		" pam"
#endif
#ifdef PASSDB_PASSWD
		" passwd"
#endif
#ifdef PASSDB_PASSWD_FILE
		" passwd-file"
#endif
#ifdef PASSDB_SHADOW 
		" shadow"
#endif
#ifdef PASSDB_SQL 
		" sql"
#endif
#ifdef PASSDB_VPOPMAIL
		" vpopmail"
#endif
	"\nUserdb:"
#ifdef USERDB_CHECKPASSWORD
		" checkpassword"
#endif
#ifdef USERDB_LDAP
		" ldap"
#ifndef BUILTIN_LDAP
		"(plugin)"
#endif
#endif
#ifdef USERDB_NSS
		" nss"
#endif
#ifdef USERDB_PASSWD
		" passwd"
#endif
#ifdef USERDB_PREFETCH
		" prefetch"
#endif
#ifdef USERDB_PASSWD_FILE
		" passwd-file"
#endif
#ifdef USERDB_SQL 
		" sql"
#endif
#ifdef USERDB_STATIC 
		" static"
#endif
#ifdef USERDB_VPOPMAIL
		" vpopmail"
#endif
	"\n");
}

int main(int argc, char *argv[])
{
	struct master_settings *set;
	unsigned int child_process_env_idx = 0;
	const char *error, *env_tz, *doveconf_arg = NULL;
	failure_callback_t *orig_info_callback, *orig_debug_callback;
	void **sets;
	bool foreground = FALSE, ask_key_pass = FALSE, log_error = FALSE;
	int c, send_signal = 0;

#ifdef DEBUG
	if (getenv("GDB") == NULL)
		fd_debug_verify_leaks(3, 1024);
	else
		child_process_env[child_process_env_idx++] = "GDB=1";
#endif
	master_service = master_service_init(MASTER_SERVICE_NAME,
				MASTER_SERVICE_FLAG_STANDALONE |
				MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR,
				&argc, &argv, "Fanp-");
	i_set_failure_prefix("");

	io_loop_set_time_moved_callback(current_ioloop, master_time_moved);

	master_uid = geteuid();
	master_gid = getegid();

	while ((c = master_getopt(master_service)) > 0) {
		if (c == '-')
			break;
		switch (c) {
		case 'F':
			foreground = TRUE;
			break;
		case 'a':
			doveconf_arg = "-a";
			break;
		case 'n':
			doveconf_arg = "-n";
			break;
		case 'p':
			/* Ask SSL private key password */
			ask_key_pass = TRUE;
			break;
		default:
			if (!master_service_parse_option(master_service,
							 c, optarg)) {
				print_help();
				exit(FATAL_DEFAULT);
			}
			break;
		}
	}

	if (doveconf_arg != NULL) {
		const char **args;

		args = t_new(const char *, 5);
		args[0] = DOVECOT_CONFIG_BIN_PATH;
		args[1] = doveconf_arg;
		args[2] = "-c";
		args[3] = master_service_get_config_path(master_service);
		args[4] = NULL;
		execv(args[0], (char **)args);
		i_fatal("execv(%s) failed: %m", args[0]);
	}

	while (optind < argc) {
		if (strcmp(argv[optind], "--version") == 0) {
			printf("%s\n", VERSION);
			return 0;
		} else if (strcmp(argv[optind], "--build-options") == 0) {
			print_build_options();
			return 0;
		} else if (strcmp(argv[optind], "--log-error") == 0) {
			log_error = TRUE;
			foreground = TRUE;
		} else if (strcmp(argv[optind], "--help") == 0) {
			print_help();
			return 0;
		} else if (strcmp(argv[optind], "reload") == 0) {
			send_signal = SIGHUP;
		} else if (strcmp(argv[optind], "stop") == 0) {
			send_signal = SIGTERM;
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[optind]);
		}
		optind++;
	}

	do {
		null_fd = open("/dev/null", O_WRONLY);
		if (null_fd == -1)
			i_fatal("Can't open /dev/null: %m");
		fd_close_on_exec(null_fd, TRUE);
	} while (null_fd <= STDERR_FILENO);

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	sets = master_service_settings_get_others(master_service);
	set = sets[0];

	if (ask_key_pass) {
		askpass("Give the password for SSL keys: ",
			ssl_manual_key_password,
			sizeof(ssl_manual_key_password));
	}

	if (dup2(null_fd, STDIN_FILENO) < 0 ||
	    dup2(null_fd, STDOUT_FILENO) < 0)
		i_fatal("dup2(null_fd) failed: %m");

	pidfile_path =
		i_strconcat(set->base_dir, "/"MASTER_PID_FILE_NAME, NULL);
	if (send_signal != 0)
		send_master_signal(send_signal);

	master_service_init_log(master_service, "master: ");
	i_get_failure_handlers(&orig_fatal_callback, &orig_error_callback,
			       &orig_info_callback, &orig_debug_callback);
	i_set_fatal_handler(startup_fatal_handler);
	i_set_error_handler(startup_error_handler);

	if (!log_error) {
		pid_file_check_running(pidfile_path);
		master_settings_do_fixes(set);
		fatal_log_check(set);
	}

	/* save TZ environment. AIX depends on it to get the timezone
	   correctly. */
	env_tz = getenv("TZ");

	/* clean up the environment of everything */
	env_clean();

	/* put back the TZ */
	if (env_tz != NULL) {
		const char *env = t_strconcat("TZ=", env_tz, NULL);

		env_put(env);
		child_process_env[child_process_env_idx++] = env;
	}
	i_assert(child_process_env_idx <
		 sizeof(child_process_env) / sizeof(child_process_env[0]));
	child_process_env[child_process_env_idx++] = NULL;

	/* create service structures from settings. if there are any errors in
	   service configuration we'll catch it here. */
	service_pids_init();
	service_anvil_global_init();
	if (services_create(set, child_process_env, &services, &error) < 0)
		i_fatal("%s", error);

	services->config->config_file_path = get_full_config_path(services);

	if (!log_error) {
		/* if any listening fails, fail completely */
		if (services_listen(services) <= 0)
			i_fatal("Failed to start listeners");

		if (!foreground)
			daemonize();
		if (chdir(set->base_dir) < 0)
			i_fatal("chdir(%s) failed: %m", set->base_dir);
	}

	i_set_fatal_handler(master_fatal_callback);
	i_set_error_handler(orig_error_callback);

	main_init(set, log_error);
	master_service_run(master_service, NULL);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
