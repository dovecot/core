/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "network.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "write-full.h"
#include "restrict-process-size.h"

#include "askpass.h"
#include "auth-process.h"
#include "capabilities.h"
#include "dict-process.h"
#include "login-process.h"
#include "mail-process.h"
#include "syslog-util.h"
#include "listener.h"
#include "ssl-init.h"
#include "log.h"
#include "sysinfo-get.h"
#include "hostpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>

/* Try to raise our fd limit this high at startup. If the limit is already
   higher, it's not dropped. */
#define DOVECOT_MASTER_FD_MIN_LIMIT 65536

#define FATAL_FILENAME "master-fatal.lastlog"

static const char *configfile = SYSCONFDIR "/" PACKAGE ".conf";
static pid_t master_original_pid;

struct ioloop *ioloop;
int null_fd = -1, inetd_login_fd;
uid_t master_uid;
char program_path[PATH_MAX];
char ssl_manual_key_password[100];
const char *env_tz;
bool auth_success_written;
bool core_dumps_disabled;
#ifdef DEBUG
bool gdb;
#endif

static void ATTR_NORETURN ATTR_FORMAT(3, 0)
master_fatal_callback(enum log_type type, int status,
		      const char *format, va_list args)
{
	const struct settings *set = settings_root->defaults;
	const char *path, *str;
	va_list args2;
	int fd;

	/* if we already forked a child process, this isn't fatal for the
	   main process and there's no need to write the fatal file. */
	if (getpid() == master_original_pid) {
		/* write the error message to a file */
		path = t_strconcat(set->base_dir, "/"FATAL_FILENAME, NULL);
		fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if (fd != -1) {
			VA_COPY(args2, args);
			str = t_strdup_vprintf(format, args2);
			write_full(fd, str, strlen(str));
			(void)close(fd);
		}
	}

	/* write it to log as well */
	if (*set->log_path == '\0')
		i_syslog_fatal_handler(type, status, format, args);
	else
		default_fatal_handler(type, status, format, args);
}

static void fatal_log_check(void)
{
	const struct settings *set = settings_root->defaults;
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

static void auth_warning_print(const struct server_settings *set)
{
	struct stat st;

	auth_success_written = stat(AUTH_SUCCESS_PATH, &st) == 0;
	if (!auth_success_written && !set->auths->debug &&
	    strcmp(set->defaults->protocols, "none") != 0) {
		i_info("If you have trouble with authentication failures,\n"
		       "enable auth_debug setting. "
		       "See http://wiki.dovecot.org/WhyDoesItNotWork");

	}
}

static void set_logfile(struct settings *set)
{
	int facility;

	if (*set->log_path == '\0') {
		if (!syslog_facility_find(set->syslog_facility, &facility))
			facility = LOG_MAIL;

		i_set_failure_syslog("dovecot", LOG_NDELAY, facility);
	} else {
		/* log to file or stderr */
		i_set_failure_file(set->log_path, "dovecot: ");
	}
	i_set_fatal_handler(master_fatal_callback);

	if (*set->info_log_path != '\0')
		i_set_info_file(set->info_log_path);

	i_set_failure_timestamp_format(set->log_timestamp);
}

static void settings_reload(void)
{
	struct server_settings *old_set = settings_root;

	i_warning("SIGHUP received - reloading configuration");

	/* restart auth and login processes */
        login_processes_destroy_all();
        auth_processes_destroy_all();
        dict_processes_kill();

	/* see if hostname changed */
	hostpid_init();

	if (!master_settings_read(configfile, FALSE, FALSE))
		i_warning("Invalid configuration, keeping old one");
	else {
		if (!IS_INETD())
			listeners_open_fds(old_set, TRUE);
                set_logfile(settings_root->defaults);
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

static void sig_reload_settings(int signo ATTR_UNUSED,
				void *context ATTR_UNUSED)
{
	settings_reload();
}

static void sig_reopen_logs(int signo ATTR_UNUSED,
			    void *context ATTR_UNUSED)
{
	set_logfile(settings_root->defaults);
}

static bool have_stderr_set(struct settings *set)
{
	if (*set->log_path != '\0' &&
	    strcmp(set->log_path, "/dev/stderr") == 0)
		return TRUE;

	if (*set->info_log_path != '\0' &&
	    strcmp(set->info_log_path, "/dev/stderr") == 0)
		return TRUE;

	return FALSE;
}

static bool have_stderr(struct server_settings *server)
{
	while (server != NULL) {
		if (server->imap != NULL && have_stderr_set(server->imap))
			return TRUE;
		if (server->pop3 != NULL && have_stderr_set(server->pop3))
			return TRUE;

		server = server->next;
	}

	return FALSE;
}

static void open_null_fd(void)
{
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd == -1)
		i_fatal("Can't open /dev/null: %m");
	fd_close_on_exec(null_fd, TRUE);
}

static void open_fds(void)
{
	/* make sure all fds between 0..3 are used. */
	while (null_fd < 4) {
		null_fd = dup(null_fd);
		if (null_fd == -1)
			i_fatal("dup(null_fd) failed: %m");
		fd_close_on_exec(null_fd, TRUE);
	}

	if (!IS_INETD()) {
		T_BEGIN {
			listeners_open_fds(NULL, FALSE);
		} T_END;
	}

	/* close stdin and stdout. */
	if (dup2(null_fd, 0) < 0)
		i_fatal("dup2(0) failed: %m");
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(1) failed: %m");
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

	set_logfile(settings_root->defaults);
	/* close stderr unless we're logging into /dev/stderr. */
	if (!have_stderr(settings_root)) {
		if (dup2(null_fd, 2) < 0)
			i_fatal("dup2(2) failed: %m");
	}

	if (log_error) {
		printf("Writing to error logs and killing myself..\n");
		i_info("This is Dovecot's info log");
		i_warning("This is Dovecot's warning log");
		i_error("This is Dovecot's error log");
		i_fatal("This is Dovecot's fatal log");
	}
	main_log_startup();

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
        lib_signals_set_handler(SIGHUP, TRUE, sig_reload_settings, NULL);
        lib_signals_set_handler(SIGUSR1, TRUE, sig_reopen_logs, NULL);

	child_processes_init();
	log_init();
	ssl_init();
	dict_processes_init();
	auth_processes_init();
	login_processes_init();
	mail_processes_init();

	create_pid_file(t_strconcat(settings_root->defaults->base_dir,
				    "/master.pid", NULL));
}

static void main_deinit(void)
{
	(void)unlink(t_strconcat(settings_root->defaults->base_dir,
				 "/master.pid", NULL));

	login_processes_destroy_all();

	mail_processes_deinit();
	login_processes_deinit();
	auth_processes_deinit();
	dict_processes_deinit();
	ssl_deinit();

	listeners_close_fds();

	if (close(null_fd) < 0)
		i_error("close(null_fd) failed: %m");

	log_deinit();
	/* log_deinit() may still want to look up child processes */
	child_processes_deinit();
	lib_signals_deinit();
	closelog();
}

static void daemonize(struct settings *set)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		i_fatal("fork() failed: %m");

	if (pid != 0)
		_exit(0);

	if (setsid() < 0)
		i_fatal("setsid() failed: %m");

	if (chdir(set->base_dir) < 0)
		i_fatal("chdir(%s) failed: %m", set->base_dir);
}

static void print_help(void)
{
	printf(
"Usage: dovecot [-F] [-c <config file>] [-p] [-n] [-a]\n"
"       [--version] [--build-options] [--exec-mail <protocol> [<args>]]\n");
}

static void print_build_options(void)
{
	static const char *build_options =
		"Build options:"
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
	"SQL drivers:"
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
#ifdef PASSDB_SIA
		" sia"
#endif
#ifdef PASSDB_SQL 
		" sql"
#endif
#ifdef PASSDB_VPOPMAIL
		" vpopmail"
#endif
	"\nUserdb:"
#ifdef USERDB_NSS
		" nss"
#endif
#ifdef USERDB_LDAP
		" ldap"
#endif
#ifdef USERDB_PASSWD
		" passwd"
#endif
#ifdef USERDB_PASSWD_FILE
		" passwd-file"
#endif
#ifdef USERDB_PREFETCH
		" prefetch"
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
	"\n";
	puts(build_options);
}

int main(int argc, char *argv[])
{
	/* parse arguments */
	const char *exec_protocol = NULL, **exec_args = NULL, *user, *home;
	bool foreground = FALSE, ask_key_pass = FALSE, log_error = FALSE;
	bool dump_config = FALSE, dump_config_nondefaults = FALSE;
	int i;

#ifdef DEBUG
	gdb = getenv("GDB") != NULL;
#endif
	lib_init();

	master_uid = geteuid();
        inetd_login_fd = -1;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-F") == 0) {
			/* foreground */
			foreground = TRUE;
		} else if (strcmp(argv[i], "-a") == 0) {
			dump_config = TRUE;
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file */
			i++;
			if (i == argc) i_fatal("Missing config file argument");
			configfile = argv[i];
		} else if (strcmp(argv[i], "-n") == 0) {
			dump_config_nondefaults = dump_config = TRUE;
		} else if (strcmp(argv[i], "-p") == 0) {
			/* Ask SSL private key password */
			ask_key_pass = TRUE;
		} else if (strcmp(argv[i], "--exec-mail") == 0) {
			/* <protocol> [<args>]
			   read configuration and execute mail process */
			i++;
			if (i == argc) i_fatal("Missing protocol argument");
			exec_protocol = argv[i];
			exec_args = (const char **)&argv[i+1];
			break;
		} else if (strcmp(argv[i], "--version") == 0) {
			printf("%s\n", VERSION);
			return 0;
		} else if (strcmp(argv[i], "--build-options") == 0) {
			print_build_options();
			return 0;
		} else if (strcmp(argv[i], "--log-error") == 0) {
			log_error = TRUE;
			foreground = TRUE;
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[1]);
		}
	}

	/* need to have this open before reading settings */
	open_null_fd();

	if (getenv("DOVECOT_INETD") != NULL) {
		/* starting through inetd. */
		inetd_login_fd = dup(0);
		if (inetd_login_fd == -1)
			i_fatal("dup(0) failed: %m");
		fd_close_on_exec(inetd_login_fd, TRUE);
		foreground = TRUE;
	}

	if (dump_config) {

		/* print the config file path before parsing it, so in case
		   of errors it's still shown */
		printf("# "VERSION": %s\n", configfile);
	}

	/* read and verify settings before forking */
	T_BEGIN {
		master_settings_init();
		if (!master_settings_read(configfile, exec_protocol != NULL,
					  dump_config || log_error))
			i_fatal("Invalid configuration in %s", configfile);
	} T_END;

	if (dump_config) {
		const char *info;

		info = sysinfo_get(settings_root->defaults->mail_location);
		if (*info != '\0')
			printf("# %s\n", info);

		master_settings_dump(settings_root, dump_config_nondefaults);
		return 0;
	}

	if (ask_key_pass) T_BEGIN {
		const char *prompt;

		prompt = t_strdup_printf("Give the password for SSL key file "
					 "%s: ",
					 settings_root->defaults->ssl_key_file);
		askpass(prompt, ssl_manual_key_password,
			sizeof(ssl_manual_key_password));
	} T_END;

	/* save TZ environment. AIX depends on it to get the timezone
	   correctly. */
	env_tz = getenv("TZ");
	user = getenv("USER");
	home = getenv("HOME");

	/* clean up the environment of everything */
	env_clean();

	/* put back the TZ */
	if (env_tz != NULL)
		env_put(t_strconcat("TZ=", env_tz, NULL));

	if (exec_protocol != NULL) {
		/* Put back user and home */
		env_put(t_strconcat("USER=", user, NULL));
		env_put(t_strconcat("HOME=", home, NULL));
		mail_process_exec(exec_protocol, exec_args);
	}

	if (!log_error)
		open_fds();

	fatal_log_check();
	auth_warning_print(settings_root);
	if (!foreground)
		daemonize(settings_root->defaults);
	master_original_pid = getpid();

	ioloop = io_loop_create();

	main_init(log_error);
        io_loop_run(ioloop);
	main_deinit();

	master_settings_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();

        return 0;
}
