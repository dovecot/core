/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "network.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "write-full.h"

#include "askpass.h"
#include "auth-process.h"
#include "dict-process.h"
#include "login-process.h"
#include "mail-process.h"
#include "syslog-util.h"
#include "ssl-init.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

const char *process_names[PROCESS_TYPE_MAX] = {
	"unknown",
	"auth",
	"auth-worker",
	"login",
	"imap",
	"pop3",
	"ssl-build-param",
	"dict"
};

/* the capabilities that we *need* in order to operate */
#ifdef HAVE_LIBCAP
cap_t caps;
cap_value_t suidcaps[] = {
	CAP_CHOWN,
	CAP_SYS_CHROOT,
	CAP_SETUID,
	CAP_SETGID,
	CAP_NET_BIND_SERVICE
};
#endif

static const char *configfile = SYSCONFDIR "/" PACKAGE ".conf";
static const char *env_tz;

struct ioloop *ioloop;
struct hash_table *pids;
int null_fd = -1, inetd_login_fd;
uid_t master_uid;
char program_path[PATH_MAX];
char ssl_manual_key_password[100];
#ifdef DEBUG
static bool gdb;
#endif

static void listen_fds_open(bool retry);
static void listen_fds_close(struct server_settings *server);

bool validate_str(const char *str, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (str[i] == '\0')
			return TRUE;
	}

	return FALSE;
}

void child_process_init_env(void)
{
	int facility;

	/* remove all environment, we don't need them */
	env_clean();

	/* we'll log through master process */
	env_put("LOG_TO_MASTER=1");
	if (env_tz != NULL)
		env_put(t_strconcat("TZ=", env_tz, NULL));

	if (settings_root == NULL ||
	    !syslog_facility_find(settings_root->defaults->syslog_facility,
				  &facility))
		facility = LOG_MAIL;
	env_put(t_strdup_printf("SYSLOG_FACILITY=%d", facility));

	if (settings_root != NULL && !settings_root->defaults->version_ignore)
		env_put("DOVECOT_VERSION="PACKAGE_VERSION);
#ifdef DEBUG
	if (gdb) env_put("GDB=1");
#endif
}

void client_process_exec(const char *cmd, const char *title)
{
	const char *executable, *p, **argv;

	/* very simple argument splitting. */
	if (*title == '\0')
		argv = t_strsplit(cmd, " ");
	else
		argv = t_strsplit(t_strconcat(cmd, " ", title, NULL), " ");

	executable = argv[0];

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	execv(executable, (char **)argv);
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
        dict_process_kill();

	if (!master_settings_read(configfile, FALSE, FALSE))
		i_warning("Invalid configuration, keeping old one");
	else {
		if (!IS_INETD()) {
			listen_fds_close(old_set);
			listen_fds_open(TRUE);
		}
                set_logfile(settings_root->defaults);
	}
}

static void sig_die(int signo, void *context __attr_unused__)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static void sig_reload_settings(int signo __attr_unused__,
				void *context __attr_unused__)
{
	settings_reload();
}

static void sig_reopen_logs(int signo __attr_unused__,
			    void *context __attr_unused__)
{
	set_logfile(settings_root->defaults);
}

static const char *get_exit_status_message(enum fatal_exit_status status)
{
	switch (status) {
	case FATAL_LOGOPEN:
		return "Can't open log file";
	case FATAL_LOGWRITE:
		return "Can't write to log file";
	case FATAL_LOGERROR:
		return "Internal logging error";
	case FATAL_OUTOFMEM:
		return "Out of memory";
	case FATAL_EXEC:
		return "exec() failed";

	case FATAL_DEFAULT:
		return NULL;
	}

	return NULL;
}

static void sigchld_handler(int signo __attr_unused__,
			    void *context __attr_unused__)
{
	const char *process_type_name, *msg;
	pid_t pid;
	int status, process_type;
	bool abnormal_exit;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* get the type and remove from hash */
		process_type = PID_GET_PROCESS_TYPE(pid);
		if (process_type != PROCESS_TYPE_UNKNOWN)
			PID_REMOVE_PROCESS_TYPE(pid);

		abnormal_exit = TRUE;

		/* write errors to syslog */
		process_type_name = process_names[process_type];
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if (status == 0) {
				abnormal_exit = FALSE;
				if (process_type == PROCESS_TYPE_UNKNOWN) {
					i_error("unknown child %s exited "
						"successfully", dec2str(pid));
				}
			} else {
				msg = get_exit_status_message(status);
				msg = msg == NULL ? "" :
					t_strconcat(" (", msg, ")", NULL);
				i_error("child %s (%s) returned error %d%s",
					dec2str(pid), process_type_name,
					status, msg);
			}
		} else if (WIFSIGNALED(status)) {
			i_error("child %s (%s) killed with signal %d",
				dec2str(pid), process_type_name,
				WTERMSIG(status));
		}

		switch (process_type) {
		case PROCESS_TYPE_LOGIN:
			login_process_destroyed(pid, abnormal_exit);
			break;
		case PROCESS_TYPE_IMAP:
		case PROCESS_TYPE_POP3:
			mail_process_destroyed(pid);
			break;
		case PROCESS_TYPE_SSL_PARAM:
			ssl_parameter_process_destroyed(pid);
			break;
		case PROCESS_TYPE_DICT:
			dict_process_restart();
			break;
		}
	}

	if (pid == -1 && errno != EINTR && errno != ECHILD)
		i_warning("waitpid() failed: %m");
}

static void resolve_ip(const char *set_name, const char *name,
		       struct ip_addr *ip, unsigned int *port)
{
	struct ip_addr *ip_list;
	const char *p;
	unsigned int ips_count;
	int ret;

	if (*name == '\0') {
                /* defaults to "*" or "[::]" */
		ip->family = 0;
		return;
	}

	if (name[0] == '[') {
		/* IPv6 address */
		p = strchr(name, ']');
		if (p == NULL) {
			i_fatal("%s: Missing ']' in address %s",
				set_name, name);
		}
		name = t_strdup_until(name+1, p);

		p++;
		if (*p == '\0')
			p = NULL;
		else if (*p != ':') {
			i_fatal("%s: Invalid data after ']' in address %s",
				set_name, name);
		}
	} else {
		p = strrchr(name, ':');
		if (p != NULL)
			name = t_strdup_until(name, p);
	}

	if (p != NULL) {
		if (!is_numeric(p+1, '\0')) {
			i_fatal("%s: Invalid port in address %s",
				set_name, name);
		}
		*port = atoi(p+1);
	}

	if (strcmp(name, "*") == 0) {
		/* IPv4 any */
		net_get_ip_any4(ip);
		return;
	}

	if (strcmp(name, "::") == 0) {
		/* IPv6 any */
		net_get_ip_any6(ip);
		return;
	}

	/* Return the first IP if there happens to be multiple. */
	ret = net_gethostbyname(name, &ip_list, &ips_count);
	if (ret != 0) {
		i_fatal("%s: Can't resolve address %s: %s",
			set_name, name, net_gethosterror(ret));
	}

	if (ips_count < 1)
		i_fatal("%s: No IPs for address: %s", set_name, name);

	*ip = ip_list[0];
}

static void
check_conflicts_set(const struct settings *set, const struct ip_addr *ip,
		    unsigned int port, const char *name1, const char *name2)
{
	if (set->listen_port == port && net_ip_compare(ip, &set->listen_ip) &&
	    set->listen_fd > 0) {
		i_fatal("Protocols %s and %s are listening in same ip/port",
			name1, name2);
	}
	if (set->ssl_listen_port == port &&
	    net_ip_compare(ip, &set->ssl_listen_ip) && set->ssl_listen_fd > 0) {
		i_fatal("Protocols %ss and %s are listening in same ip/port",
			name1, name2);
	}
}

static void check_conflicts(const struct ip_addr *ip, unsigned int port,
			    const char *proto)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL) {
			check_conflicts_set(server->imap, ip, port,
					    "imap", proto);
		}
		if (server->pop3 != NULL) {
			check_conflicts_set(server->pop3, ip, port,
					    "pop3", proto);
		}
	}
}

static void listen_protocols(struct settings *set, bool retry)
{
	struct ip_addr *ip;
	const char *const *proto;
	unsigned int port;
	int *fd, i;

	set->listen_port = set->protocol == MAIL_PROTOCOL_IMAP ? 143 : 110;
#ifdef HAVE_SSL
	set->ssl_listen_port = set->protocol == MAIL_PROTOCOL_IMAP ? 993 : 995;
#else
	set->ssl_listen_port = 0;
#endif

	/* resolve */
	resolve_ip("listen", set->listen, &set->listen_ip, &set->listen_port);
	if (!set->ssl_disable) {
		resolve_ip("ssl_listen", set->ssl_listen, &set->ssl_listen_ip,
			   &set->ssl_listen_port);
	}

	/* if ssl_listen wasn't explicitly set in the config file,
	   use the non-ssl IP settings for the ssl listener, too. */
	if (set->ssl_listen_ip.family == 0 && *set->ssl_listen == '\0')
		set->ssl_listen_ip = set->listen_ip;

	/* register wanted protocols */
        proto = t_strsplit_spaces(set->protocols, " ");
	for (; *proto != NULL; proto++) {
		fd = NULL; ip = NULL; port = 0;
		if (strcasecmp(*proto, "imap") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP) {
				fd = &set->listen_fd;
				port = set->listen_port;
				ip = &set->listen_ip;
			}
		} else if (strcasecmp(*proto, "imaps") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP &&
			    !set->ssl_disable) {
				fd = &set->ssl_listen_fd;
				port = set->ssl_listen_port;
				ip = &set->ssl_listen_ip;
			}
		} else if (strcasecmp(*proto, "pop3") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3) {
				fd = &set->listen_fd;
				port = set->listen_port;
				ip = &set->listen_ip;
			}
		} else if (strcasecmp(*proto, "pop3s") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3 &&
			    !set->ssl_disable) {
				fd = &set->ssl_listen_fd;
				port = set->ssl_listen_port;
				ip = &set->ssl_listen_ip;
			}
		} else {
			i_fatal("Unknown protocol %s", *proto);
		}

		if (fd == NULL)
			continue;

		if (*fd != -1)
			i_fatal("Protocol %s given more than once", *proto);

		if (port == 0)
			*fd = null_fd;
		else {
			for (i = 0; i < 10; i++) {
				*fd = net_listen(ip, &port, 8);
				if (*fd != -1)
					break;
				if (errno == EADDRINUSE) {
					/* retry */
				} else if (errno == EINTR &&
					   io_loop_is_running(ioloop)) {
					/* SIGHUPing sometimes gets us here.
					   we don't want to die. */
				} else {
					/* error */
					break;
				}

				check_conflicts(ip, port, *proto);
				if (!retry)
					break;

				/* wait a while and try again. we're SIGHUPing
				   so we most likely just closed it ourself.. */
				sleep(1);
			}

			if (*fd == -1)
				i_fatal("listen(%d) failed: %m", port);
			net_set_nonblock(*fd, TRUE);
			fd_close_on_exec(*fd, TRUE);
		}
	}

	if (set->listen_fd == -1)
		set->listen_fd = null_fd;
	if (set->ssl_listen_fd == -1)
		set->ssl_listen_fd = null_fd;
}

static void listen_fds_open(bool retry)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL)
			listen_protocols(server->imap, retry);
		if (server->pop3 != NULL)
			listen_protocols(server->pop3, retry);
	}
}

static void listen_fds_close(struct server_settings *server)
{
	for (; server != NULL; server = server->next) {
		if (server->imap != NULL) {
			if (server->imap->listen_fd != null_fd &&
			    close(server->imap->listen_fd) < 0)
				i_error("close(imap.listen_fd) failed: %m");
			if (server->imap->ssl_listen_fd != null_fd &&
			    close(server->imap->ssl_listen_fd) < 0)
				i_error("close(imap.ssl_listen_fd) failed: %m");
		}
		if (server->pop3 != NULL) {
			if (server->pop3->listen_fd != null_fd &&
			    close(server->pop3->listen_fd) < 0)
				i_error("close(pop3.listen_fd) failed: %m");
			if (server->pop3->ssl_listen_fd != null_fd &&
			    close(server->pop3->ssl_listen_fd) < 0)
				i_error("close(pop3.ssl_listen_fd) failed: %m");
		}
	}
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

	if (!IS_INETD())
		listen_fds_open(FALSE);

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

static void main_init(bool log_error)
{
	/* deny file access from everyone else except owner */
        (void)umask(0077);

	/* close stderr unless we're logging into /dev/stderr. keep as little
	   distance between closing it and opening the actual log file so that
	   we don't lose anything. */
	if (!have_stderr(settings_root)) {
		if (dup2(null_fd, 2) < 0)
			i_fatal("dup2(2) failed: %m");
	}

	set_logfile(settings_root->defaults);
	i_info("Dovecot v"VERSION" starting up");

	log_init();

	if (log_error)
		i_fatal("This is Dovecot's error log");

#ifdef HAVE_LIBCAP
	/* drop capabilities that we don't need, be very restrictive. */
	caps = cap_init();
	cap_clear(caps);
	cap_set_flag(caps, CAP_PERMITTED,
		     sizeof(suidcaps) / sizeof(cap_value_t), suidcaps, CAP_SET);
	cap_set_flag(caps, CAP_EFFECTIVE,
		     sizeof(suidcaps) / sizeof(cap_value_t), suidcaps, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
#endif

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
        lib_signals_set_handler(SIGHUP, TRUE, sig_reload_settings, NULL);
        lib_signals_set_handler(SIGUSR1, TRUE, sig_reopen_logs, NULL);

	pids = hash_create(default_pool, default_pool, 128, NULL, NULL);
	lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, NULL);

	ssl_init();
	dict_process_init();
	auth_processes_init();
	login_processes_init();

	create_pid_file(t_strconcat(settings_root->defaults->base_dir,
				    "/master.pid", NULL));
}

static void main_deinit(void)
{
	(void)unlink(t_strconcat(settings_root->defaults->base_dir,
				 "/master.pid", NULL));

	/* make sure we log if child processes died unexpectedly */
	sigchld_handler(SIGCHLD, NULL);

	login_processes_deinit();
	auth_processes_deinit();
	dict_process_deinit();
	ssl_deinit();

	lib_signals_unset_handler(SIGCHLD, sigchld_handler, NULL);

	if (close(null_fd) < 0)
		i_error("close(null_fd) failed: %m");

	hash_destroy(pids);
	lib_signals_deinit();
	log_deinit();
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
"       [--exec-mail <protocol>] [--version] [--build-options]\n");
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
	/* parse arguments */
	const char *exec_protocol = NULL, *exec_section = NULL, *user, *home;
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
			/* <protocol> [<server section>]
			   read configuration and execute mail process */
			i++;
			if (i == argc) i_fatal("Missing protocol argument");
			exec_protocol = argv[i];
			if (i+1 != argc) 
				exec_section = argv[++i];
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
		printf("# %s\n", configfile);
	}

	/* read and verify settings before forking */
	t_push();
	master_settings_init();
	if (!master_settings_read(configfile, exec_protocol != NULL,
				  dump_config))
		exit(FATAL_DEFAULT);
	t_pop();

	if (dump_config) {
		master_settings_dump(settings_root, dump_config_nondefaults);
		return 0;
	}

	if (ask_key_pass) {
		const char *prompt;

		t_push();
		prompt = t_strdup_printf("Give the password for SSL key file "
					 "%s: ",
					 settings_root->defaults->ssl_key_file);
		askpass(prompt, ssl_manual_key_password,
			sizeof(ssl_manual_key_password));
		t_pop();
	}

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
		mail_process_exec(exec_protocol, exec_section);
	}

	open_fds();

	if (!foreground)
		daemonize(settings_root->defaults);

	ioloop = io_loop_create();

	main_init(log_error);
        io_loop_run(ioloop);
	main_deinit();

	master_settings_deinit();
	io_loop_destroy(&ioloop);
	lib_deinit();

        return 0;
}
