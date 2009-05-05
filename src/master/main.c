/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "fd-close-on-exec.h"
#include "array.h"
#include "write-full.h"
#include "env-util.h"
#include "hostpid.h"
#include "restrict-process-size.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "capabilities.h"
#include "service.h"
#include "service-listen.h"
#include "service-monitor.h"
#include "service-log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#define FATAL_FILENAME "master-fatal.lastlog"
#define MASTER_PID_FILE_NAME "master.pid"

struct master_service *master_service;
uid_t master_uid;
gid_t master_gid;
bool auth_success_written;
bool core_dumps_disabled;
int null_fd;

static char *pidfile_path;
static struct service_list *services;
static fatal_failure_callback_t *orig_fatal_callback;

static const char *child_process_env[3]; /* @UNSAFE */

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

	execv(executable, (char **)argv);
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);
}

int get_uidgid(const char *user, uid_t *uid_r, gid_t *gid_r,
	       const char **error_r)
{
	struct passwd *pw;

	if (*user == '\0') {
		*uid_r = (uid_t)-1;
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
		i_warning("Last died with error (see error log for more "
			  "information): %s", buf);
	}

	close(fd);
	if (unlink(path) < 0)
		i_error("unlink(%s) failed: %m", path);
}

static bool
services_has_name(const struct master_settings *set, const char *name)
{
	struct service_settings *const *services;
	unsigned int i, count;

	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(services[i]->name, name) == 0)
			return TRUE;
	}
	return FALSE;
}

static bool services_have_auth_destinations(const struct master_settings *set)
{
	struct service_settings *const *services;
	unsigned int i, count;

	services = array_get(&set->services, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(services[i]->type, "auth-source") == 0) {
			if (services_has_name(set, services[i]->auth_dest_service))
				return TRUE;
		}
	}
	return FALSE;
}

static bool auths_have_debug(const struct master_settings *set)
{
	struct master_auth_settings *const *auths;
	unsigned int i, count;

	if (!array_is_created(&set->auths))
		return FALSE;

	auths = array_get(&set->auths, &count);
	for (i = 0; i < count; i++) {
		if (auths[i]->debug)
			return TRUE;
	}
	return FALSE;
}

static void auth_warning_print(const struct master_settings *set)
{
	struct stat st;

	auth_success_written = stat(AUTH_SUCCESS_PATH, &st) == 0;
	if (!auth_success_written && !auths_have_debug(set) &&
	    services_have_auth_destinations(set)) {
		i_info("If you have trouble with authentication failures,\n"
		       "enable auth_debug setting. "
		       "See http://wiki.dovecot.org/WhyDoesItNotWork");

	}
}

static void pid_file_check_running(const char *path)
{
	char buf[32];
	int fd;
	ssize_t ret;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret == 0)
			i_error("Empty PID file in %s, overriding", path);
		else
			i_fatal("read(%s) failed: %m", path);
	} else {
		pid_t pid;

		if (buf[ret-1] == '\n')
			ret--;
		buf[ret] = '\0';
		pid = atoi(buf);
		if (pid == getpid() || (kill(pid, 0) < 0 && errno == ESRCH)) {
			/* doesn't exist */
		} else {
			i_fatal("Dovecot is already running with PID %s "
				"(read from %s)", buf, path);
		}
	}
	(void)close(fd);
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

static void
sig_settings_reload(const siginfo_t *si ATTR_UNUSED,
		    void *context ATTR_UNUSED)
{
	struct master_settings *new_set;
	struct service_list *new_services;
	const char *error;
	pool_t pool;

	/* see if hostname changed */
	hostpid_init();

#if 0 // FIXME
	/* FIXME: this loses process structures for existing processes.
	   figure out something. */
	new_set = master_settings_read(pool, config_binary, config_path);
	new_services = new_set == NULL ? NULL :
		services_create(new_set, child_process_env, &error);
#endif
	if (new_services == NULL) {
		/* new configuration is invalid, keep the old */
		i_error("Config reload failed: %s", error);
		return;
	}

	/* switch to new configuration. */
	(void)services_listen_using(new_services, services);
	services_destroy(services);
	services = new_services;

        services_monitor_start(services);
}

static void
sig_log_reopen(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
        service_signal(services->log, SIGUSR1);
}

static void
sig_reap_children(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	services_monitor_reap_children(services);
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

static void main_init(bool log_error)
{
	drop_capabilities();

	/* deny file access from everyone else except owner */
        (void)umask(0077);

	if (log_error) {
		printf("Writing to error logs and killing myself..\n");
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

	services_monitor_start(services);
}

static void main_deinit(void)
{
	if (unlink(pidfile_path) < 0)
		i_error("unlink(%s) failed: %m", pidfile_path);
	i_free(pidfile_path);

	services_destroy(services);
}

static const char *get_full_config_path(struct service_list *list)
{
	const char *path;
	char cwd[PATH_MAX];

	path = master_service_get_config_path(master_service);
	if (*path == '/')
		return path;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		i_fatal("getcwd() failed: %m");
	return p_strconcat(list->pool, cwd, "/", path, NULL);
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
	printf(
"Usage: dovecot [-F] [-c <config file>] [-p] [-n] [-a]\n"
"       [-cb <config binary path>] [--version] [--build-options]\n");
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
	"\nSQL drivers:"
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
	static const struct setting_parser_info *set_roots[] = {
		&master_setting_parser_info,
		NULL
	};
	struct master_settings *set;
	unsigned int child_process_env_idx = 0;
	const char *getopt_str, *error, *env_tz;
	failure_callback_t *error_callback;
	void **sets;
	bool foreground = FALSE, ask_key_pass = FALSE, log_error = FALSE;
	int c;

#ifdef DEBUG
	if (getenv("GDB") == NULL)
		fd_debug_verify_leaks(3, 1024);
	else
		child_process_env[child_process_env_idx++] = "GDB=1";
#endif
	master_service = master_service_init("master", 0, argc, argv);

	master_uid = geteuid();
	master_gid = getegid();

	getopt_str = t_strconcat("Fp", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'F':
			foreground = TRUE;
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

	if (optind < argc) {
		if (strcmp(argv[optind], "--version") == 0) {
			printf("%s\n", VERSION);
			return 0;
		} else if (strcmp(argv[optind], "--build-options") == 0) {
			print_build_options();
			return 0;
		} else if (strcmp(argv[optind], "--log-error") == 0) {
			log_error = TRUE;
			foreground = TRUE;
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[optind]);
		}
	}

	do {
		null_fd = open("/dev/null", O_WRONLY);
		if (null_fd == -1)
			i_fatal("Can't open /dev/null: %m");
		fd_close_on_exec(null_fd, TRUE);
	} while (null_fd <= STDERR_FILENO);

	if (dup2(null_fd, STDIN_FILENO) < 0 ||
	    dup2(null_fd, STDOUT_FILENO) < 0)
		i_fatal("dup2(null_fd) failed: %m");

	if (master_service_settings_read(master_service, set_roots, NULL, FALSE,
					 &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	sets = master_service_settings_get_others(master_service);
	set = sets[0];

	pidfile_path =
		i_strconcat(set->base_dir, "/"MASTER_PID_FILE_NAME, NULL);
	if (!log_error) {
		pid_file_check_running(pidfile_path);
		master_settings_do_fixes(set);
		fatal_log_check(set);
		auth_warning_print(set);
	}

#if 0 // FIXME
	if (ask_key_pass) {
		const char *prompt;

		prompt = t_strdup_printf("Give the password for SSL key file "
					 "%s: ", set->ssl_key_file);
		askpass(prompt, ssl_manual_key_password,
			sizeof(ssl_manual_key_password));
	}
#endif

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
	services = services_create(set, child_process_env, &error);
	if (services == NULL)
		i_fatal("%s", error);

	services->config->config_file_path = get_full_config_path(services);

	/* if any listening fails, fail completely */
	if (services_listen(services) <= 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "dovecot: ", 0);
	i_get_failure_handlers(&orig_fatal_callback, &error_callback,
			       &error_callback);
	i_set_fatal_handler(master_fatal_callback);

	if (!foreground)
		daemonize();
	if (chdir(set->base_dir) < 0)
		i_fatal("chdir(%s) failed: %m", set->base_dir);

	main_init(log_error);
	master_service_run(master_service, NULL);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
