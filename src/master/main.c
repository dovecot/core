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
	"ssl-param"
};

static const char *configfile = SYSCONFDIR "/" PACKAGE ".conf";
static struct timeout *to;

struct ioloop *ioloop;
struct hash_table *pids;
int null_fd, mail_fd[FD_MAX];

int validate_str(const char *str, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (str[i] == '\0')
			return TRUE;
	}

	return FALSE;
}

void clean_child_process(void)
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

	master_settings_read(configfile);
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

		if (process_type == PROCESS_TYPE_MAIL)
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

	if (strcmp(name, "[::]") == 0) {
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

static void open_fds(void)
{
	struct ip_addr *imap_ip, *imaps_ip, *pop3_ip, *pop3s_ip, *ip;
	const char *const *proto;
	unsigned int imap_port = 143;
	unsigned int pop3_port = 110;
#ifdef HAVE_SSL
	unsigned int imaps_port = 993;
	unsigned int pop3s_port = 995;
#else
	unsigned int imaps_port = 0;
	unsigned int pop3s_port = 0;
#endif
	unsigned int port;
	int *fd, i;

	/* resolve */
	imap_ip = resolve_ip(set->imap_listen, &imap_port);
	imaps_ip = resolve_ip(set->imaps_listen, &imaps_port);
	pop3_ip = resolve_ip(set->pop3_listen, &pop3_port);
	pop3s_ip = resolve_ip(set->pop3s_listen, &pop3s_port);

	if (imaps_ip == NULL && set->imaps_listen == NULL)
		imaps_ip = imap_ip;
	if (pop3s_ip == NULL && set->pop3s_listen == NULL)
		pop3s_ip = pop3_ip;

	/* initialize fds */
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd == -1)
		i_fatal("Can't open /dev/null: %m");
	fd_close_on_exec(null_fd, TRUE);

	for (i = 0; i < FD_MAX; i++)
		mail_fd[i] = -1;

	/* register wanted protocols */
	for (proto = t_strsplit(set->protocols, " "); *proto != NULL; proto++) {
		if (strcasecmp(*proto, "imap") == 0) {
			fd = &mail_fd[FD_IMAP]; ip = imap_ip; port = imap_port;
		} else if (strcasecmp(*proto, "imaps") == 0) {
			fd = &mail_fd[FD_IMAPS]; ip = imaps_ip; port = imaps_port;
		} else if (strcasecmp(*proto, "pop3") == 0) {
			fd = &mail_fd[FD_POP3]; ip = pop3_ip; port = pop3_port;
		} else if (strcasecmp(*proto, "pop3s") == 0) {
			fd = &mail_fd[FD_POP3S]; ip = pop3s_ip; port = pop3s_port;
		} else {
			i_fatal("Unknown protocol %s", *proto);
		}

		if (*fd != -1)
			i_fatal("Protocol %s given more than once", *proto);

		*fd = port == 0 ? dup(null_fd) : net_listen(ip, &port);
		if (*fd == -1)
			i_fatal("listen(%d) failed: %m", port);
		fd_close_on_exec(*fd, TRUE);
	}

	for (i = 0; i < FD_MAX; i++) {
		if (mail_fd[i] == -1) {
			mail_fd[i] = dup(null_fd);
			if (mail_fd[i] == -1)
				i_fatal("dup(mail_fd[%d]) failed: %m", i);
			fd_close_on_exec(mail_fd[i], TRUE);
		}
	}

	/* close stdin and stdout. close stderr unless we're logging
	   into /dev/stderr. */
	if (dup2(null_fd, 0) < 0)
		i_fatal("dup2(0) failed: %m");
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(1) failed: %m");

	if ((set->log_path == NULL ||
	     strcmp(set->log_path, "/dev/stderr") != 0) &&
	    (set->info_log_path == NULL ||
	     strcmp(set->info_log_path, "/dev/stderr") != 0)) {
		if (dup2(null_fd, 2) < 0)
			i_fatal("dup(0) failed: %m");
	}
}

static void open_logfile(void)
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

	open_logfile();

	lib_init_signals(sig_quit);

	pids = hash_create(default_pool, default_pool, 128, NULL, NULL);
	to = timeout_add(100, timeout_handler, NULL);

	ssl_init();
	auth_processes_init();
	login_processes_init();
}

static void main_deinit(void)
{
	int i;

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

	for (i = 0; i < FD_MAX; i++) {
		if (close(mail_fd[i]) < 0)
			i_error("close(mail_fd[%d]) failed: %m", i);
	}

	hash_destroy(pids);
	closelog();
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

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-F") == 0) {
			/* foreground */
			foreground = TRUE;
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file */
			i++;
			if (i == argc) i_fatal("Missing config file argument");
			configfile = argv[i];
		} else {
			print_help();
			i_fatal("Unknown argument: %s", argv[1]);
		}
	}

	/* read and verify settings before forking */
	master_settings_init();
	master_settings_read(configfile);
	open_fds();

	if (!foreground)
		daemonize();

	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	master_settings_deinit();
	io_loop_destroy(ioloop);
	lib_deinit();

        return 0;
}
