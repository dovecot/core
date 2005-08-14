/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "network.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "write-full.h"

#include "auth-process.h"
#include "login-process.h"
#include "mail-process.h"
#include "ssl-init.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>

const char *process_names[PROCESS_TYPE_MAX] = {
	"unknown",
	"auth",
	"auth-worker",
	"login",
	"imap",
	"pop3",
	"ssl-param"
};

static const char *configfile = SYSCONFDIR "/" PACKAGE ".conf";
static struct timeout *to;
static unsigned int settings_reload_hup_count = 0;
static unsigned int log_reopen_usr1_count = 0;
static const char *env_tz;

struct ioloop *ioloop;
struct hash_table *pids;
int null_fd, inetd_login_fd;
uid_t master_uid;
#ifdef DEBUG
static int gdb;
#endif

static void listen_fds_open(int retry);
static void listen_fds_close(struct server_settings *server);

int validate_str(const char *str, size_t max_len)
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
	/* remove all environment, we don't need them */
	env_clean();

	/* we'll log through master process */
	env_put("LOG_TO_MASTER=1");
	if (env_tz != NULL)
		env_put(t_strconcat("TZ=", env_tz, NULL));

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

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void set_logfile(struct settings *set)
{
	if (set->log_path == NULL)
		i_set_failure_syslog("dovecot", LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(set->log_path, "dovecot");
	}

	if (set->info_log_path != NULL)
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

	if (!master_settings_read(configfile, FALSE))
		i_warning("Invalid configuration, keeping old one");
	else {
		listen_fds_close(old_set);
		listen_fds_open(TRUE);
                set_logfile(settings_root->defaults);
	}
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

static void timeout_handler(void *context __attr_unused__)
{
	const char *process_type_name, *msg;
	pid_t pid;
	int status, process_type;

	if (lib_signal_hup_count != settings_reload_hup_count) {
		settings_reload_hup_count = lib_signal_hup_count;
		settings_reload();
	}
	if (lib_signal_usr1_count != log_reopen_usr1_count) {
		log_reopen_usr1_count = lib_signal_usr1_count;
                set_logfile(settings_root->defaults);
	}

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* get the type and remove from hash */
		process_type = PID_GET_PROCESS_TYPE(pid);
		PID_REMOVE_PROCESS_TYPE(pid);

		if (process_type == PROCESS_TYPE_IMAP ||
		    process_type == PROCESS_TYPE_POP3)
			mail_process_destroyed(pid);
		if (process_type == PROCESS_TYPE_SSL_PARAM)
			ssl_parameter_process_destroyed(pid);

		/* write errors to syslog */
		process_type_name = process_names[process_type];
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if (status != 0) {
				if (process_type == PROCESS_TYPE_LOGIN)
					login_process_abormal_exit(pid);

				msg = get_exit_status_message(status);
				msg = msg == NULL ? "" :
					t_strconcat(" (", msg, ")", NULL);
				i_error("child %s (%s) returned error %d%s",
					dec2str(pid), process_type_name,
					status, msg);
			}
		} else if (WIFSIGNALED(status)) {
			if (process_type == PROCESS_TYPE_LOGIN)
				login_process_abormal_exit(pid);
			i_error("child %s (%s) killed with signal %d",
				dec2str(pid), process_type_name,
				WTERMSIG(status));
		}
	}

	if (pid == -1 && errno != EINTR && errno != ECHILD)
		i_warning("waitpid() failed: %m");
}

static void resolve_ip(const char *name, struct ip_addr *ip, unsigned int *port)
{
	struct ip_addr *ip_list;
	const char *p;
	int ret, ips_count;

	if (name == NULL) {
                /* defaults to "*" or "[::]" */
		ip->family = 0;
		return;
	}

	if (name[0] == '[') {
		/* IPv6 address */
		p = strchr(name, ']');
		if (p == NULL)
			i_fatal("Missing ']' in address %s", name);

		name = t_strdup_until(name+1, p);

		p++;
		if (*p == '\0')
			p = NULL;
		else if (*p != ':')
			i_fatal("Invalid data after ']' in address %s", name);
	} else {
		p = strrchr(name, ':');
		if (p != NULL)
			name = t_strdup_until(name, p);
	}

	if (p != NULL) {
		if (!is_numeric(p+1, '\0'))
			i_fatal("Invalid port in address %s", name);
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
		i_fatal("Can't resolve address %s: %s",
			name, net_gethosterror(ret));
	}

	if (ips_count < 1)
		i_fatal("No IPs for address: %s", name);

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

static void listen_protocols(struct settings *set, int retry)
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
	resolve_ip(set->listen, &set->listen_ip, &set->listen_port);
	resolve_ip(set->ssl_listen, &set->ssl_listen_ip, &set->ssl_listen_port);

	if (set->ssl_listen_ip.family == 0 && set->ssl_listen == NULL)
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
				if (*fd != -1 || errno != EADDRINUSE)
					break;

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
		}
		fd_close_on_exec(*fd, TRUE);
	}

	if (set->listen_fd == -1)
		set->listen_fd = null_fd;
	if (set->ssl_listen_fd == -1)
		set->ssl_listen_fd = null_fd;
}

static void listen_fds_open(int retry)
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

static int have_stderr_set(struct settings *set)
{
	if (set->log_path != NULL &&
	    strcmp(set->log_path, "/dev/stderr") == 0)
		return TRUE;

	if (set->info_log_path != NULL &&
	    strcmp(set->info_log_path, "/dev/stderr") == 0)
		return TRUE;

	return FALSE;
}

static int have_stderr(struct server_settings *server)
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

static void open_fds(void)
{
	/* initialize fds. */
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd == -1)
		i_fatal("Can't open /dev/null: %m");
	fd_close_on_exec(null_fd, TRUE);

	/* make sure all fds between 0..3 are used. */
	while (null_fd < 4) {
		null_fd = dup(null_fd);
		fd_close_on_exec(null_fd, TRUE);
	}

	if (!IS_INETD())
		listen_fds_open(FALSE);

	/* close stdin and stdout. close stderr unless we're logging
	   into /dev/stderr. */
	if (dup2(null_fd, 0) < 0)
		i_fatal("dup2(0) failed: %m");
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(1) failed: %m");

	if (!have_stderr(settings_root)) {
		if (dup2(null_fd, 2) < 0)
			i_fatal("dup2(2) failed: %m");
	}
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

static void main_init(void)
{
	/* deny file access from everyone else except owner */
        (void)umask(0077);

	set_logfile(settings_root->defaults);
	i_info("Dovecot v"VERSION" starting up");

	log_init();

	lib_init_signals(sig_quit);

	pids = hash_create(default_pool, default_pool, 128, NULL, NULL);
	to = timeout_add(100, timeout_handler, NULL);

	ssl_init();
	auth_processes_init();
	login_processes_init();

	create_pid_file(t_strconcat(settings_root->defaults->base_dir,
				    "/master.pid", NULL));
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	(void)unlink(t_strconcat(settings_root->defaults->base_dir,
				 "/master.pid", NULL));

	/* make sure we log if child processes died unexpectedly */
	timeout_handler(NULL);

	login_processes_deinit();
	auth_processes_deinit();
	ssl_deinit();

	timeout_remove(to);

	if (close(null_fd) < 0)
		i_error("close(null_fd) failed: %m");

	hash_destroy(pids);
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
	printf("Usage: dovecot [-F] [-c <config file>]\n");
}

int main(int argc, char *argv[])
{
	/* parse arguments */
	const char *exec_protocol = NULL, *exec_section = NULL;
	int foreground = FALSE;
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
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file */
			i++;
			if (i == argc) i_fatal("Missing config file argument");
			configfile = argv[i];
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
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[1]);
		}
	}

	if (getenv("DOVECOT_INETD") != NULL) {
		/* starting through inetd. */
		inetd_login_fd = dup(0);
		if (inetd_login_fd == -1)
			i_fatal("dup(0) failed: %m");
		fd_close_on_exec(inetd_login_fd, TRUE);
		foreground = TRUE;
	}

	/* read and verify settings before forking */
	master_settings_init();
	if (!master_settings_read(configfile, exec_protocol != NULL))
		exit(FATAL_DEFAULT);

	if (exec_protocol != NULL)
		mail_process_exec(exec_protocol, exec_section);

	/* save TZ environment. AIX depends on it to get the timezone
	   correctly. */
	env_tz = getenv("TZ");

	/* clean up the environment of everything */
	env_clean();

	/* put back the TZ */
	if (env_tz != NULL)
		env_put(t_strconcat("TZ=", env_tz, NULL));

	open_fds();

	if (!foreground)
		daemonize(settings_root->defaults);

	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	master_settings_deinit();
	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
