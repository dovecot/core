/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "network.h"
#include "env-util.h"
#include "fd-close-on-exec.h"

#include "auth-process.h"
#include "login-process.h"
#include "mail-process.h"
#include "ssl-init.h"

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
	"login",
	"imap",
	"pop3",
	"ssl-param"
};

static const char *configfile = SYSCONFDIR "/" PACKAGE ".conf";
static struct timeout *to;

struct ioloop *ioloop;
struct hash_table *pids;
int null_fd, inetd_login_fd;
uid_t master_uid;

int validate_str(const char *str, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (str[i] == '\0')
			return TRUE;
	}

	return FALSE;
}

void child_process_init_env(struct settings *set)
{
	/* remove all environment, we don't need them */
	env_clean();

	/* set the failure log */
	if (set->log_path == NULL)
		env_put("USE_SYSLOG=1");
	else
		env_put(t_strconcat("LOGFILE=", set->log_path, NULL));

	if (set->info_log_path != NULL) {
		env_put(t_strconcat("INFOLOGFILE=",
				    set->info_log_path, NULL));
	}

	if (set->log_timestamp != NULL) {
		env_put(t_strconcat("LOGSTAMP=",
				    set->log_timestamp, NULL));
	}
}

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void settings_reload(void)
{
	i_warning("SIGHUP received - reloading configuration");

	/* restart auth and login processes */
        login_processes_destroy_all();
        auth_processes_destroy_all();

	if (!master_settings_read(configfile))
		i_warning("Invalid configuration, keeping old one");
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

	if (lib_signal_hup != 0) {
		settings_reload();
		lib_signal_hup = 0;
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

static struct ip_addr *resolve_ip(const char *name, unsigned int *port)
{
	const char *p;
	struct ip_addr *ip;
	int ret, ips_count;

	if (name == NULL)
		return NULL; /* defaults to "*" or "[::]" */

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
		ip = t_new(struct ip_addr, 1);
		net_get_ip_any4(ip);
		return ip;
	}

	if (strcmp(name, "::") == 0) {
		/* IPv6 any */
		ip = t_new(struct ip_addr, 1);
		net_get_ip_any6(ip);
		return ip;
	}

	/* Return the first IP if there happens to be multiple. */
	ret = net_gethostbyname(name, &ip, &ips_count);
	if (ret != 0) {
		i_fatal("Can't resolve address %s: %s",
			name, net_gethosterror(ret));
	}

	if (ips_count < 1)
		i_fatal("No IPs for address: %s", name);

	return ip;
}

static void listen_protocols(struct settings *set)
{
	struct ip_addr *normal_ip, *ssl_ip, *ip;
	const char *const *proto;
	unsigned int normal_port, ssl_port, port;
	int *fd;

	normal_port = set->protocol == MAIL_PROTOCOL_IMAP ? 143 : 110;
#ifdef HAVE_SSL
	ssl_port = set->protocol == MAIL_PROTOCOL_IMAP ? 993 : 995;
#else
	ssl_port = 0;
#endif

	/* resolve */
	normal_ip = resolve_ip(set->listen, &normal_port);
	ssl_ip = resolve_ip(set->ssl_listen, &ssl_port);

	if (ssl_ip == NULL && set->ssl_listen == NULL)
		ssl_ip = normal_ip;

	/* register wanted protocols */
	for (proto = t_strsplit(set->protocols, " "); *proto != NULL; proto++) {
		fd = NULL; ip = NULL; port = 0;
		if (strcasecmp(*proto, "imap") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP) {
				fd = &set->listen_fd;
				port = normal_port; ip = normal_ip;
			}
		} else if (strcasecmp(*proto, "imaps") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP &&
			    !set->ssl_disable) {
				fd = &set->ssl_listen_fd;
				port = ssl_port; ip = ssl_ip;
			}
		} else if (strcasecmp(*proto, "pop3") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3) {
				fd = &set->listen_fd;
				port = normal_port; ip = normal_ip;
			}
		} else if (strcasecmp(*proto, "pop3s") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3 &&
			    !set->ssl_disable) {
				fd = &set->ssl_listen_fd;
				port = ssl_port; ip = ssl_ip;
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
			*fd = net_listen(ip, &port);
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
	struct server_settings *server;

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

	if (!IS_INETD()) {
		server = settings_root;
		for (; server != NULL; server = server->next) {
			if (server->imap != NULL)
				listen_protocols(server->imap);
			if (server->pop3 != NULL)
				listen_protocols(server->pop3);
		}
	}

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

static void open_logfile(struct settings *set)
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

	i_info("Dovecot starting up");
}

static void main_init(void)
{
	/* deny file access from everyone else except owner */
        (void)umask(0077);

	open_logfile(settings_root->defaults);

	lib_init_signals(sig_quit);

	pids = hash_create(default_pool, default_pool, 128, NULL, NULL);
	to = timeout_add(100, timeout_handler, NULL);

	ssl_init();
	auth_processes_init();
	login_processes_init();
}

static void main_deinit(void)
{
        if (lib_signal_kill != 0)
		i_warning("Killed with signal %d", lib_signal_kill);

	/* make sure we log if child processes died unexpectedly */
	timeout_handler(NULL);

	login_processes_deinit();
	auth_processes_deinit();
	ssl_deinit();

	timeout_remove(to);

	if (close(null_fd) < 0)
		i_error("close(null_fd) failed: %m");

	hash_destroy(pids);
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
	int foreground = FALSE;
	int i;

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
		} else if (strcmp(argv[i], "--inetd") == 0) {
			/* starting through inetd. */
			inetd_login_fd = dup(0);
			if (inetd_login_fd == -1)
				i_fatal("dup(0) failed: %m");
			fd_close_on_exec(inetd_login_fd, TRUE);
			foreground = TRUE;
		} else if (strcmp(argv[i], "--version") == 0) {
			printf("%s\n", VERSION);
			return 0;
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[1]);
		}
	}

	/* read and verify settings before forking */
	master_settings_init();
	if (!master_settings_read(configfile))
		exit(FATAL_DEFAULT);
	open_fds();

	/* we don't need any environment */
	env_clean();

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
