/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "array.h"
#include "write-full.h"
#include "env-util.h"
#include "hostpid.h"
#include "path-util.h"
#include "ipwd.h"
#include "str.h"
#include "time-util.h"
#include "execv-const.h"
#include "restrict-process-size.h"
#include "settings.h"
#include "master-instance.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "log-error-buffer.h"
#include "askpass.h"
#include "capabilities.h"
#include "master-client.h"
#include "service.h"
#include "service-anvil.h"
#include "service-listen.h"
#include "service-monitor.h"
#include "service-process.h"
#include "service-log.h"
#include "dovecot-version.h"
#ifdef HAVE_LIBSYSTEMD
#  include <systemd/sd-daemon.h>
#  define i_sd_notify(unset, message) (void)sd_notify((unset), (message))
#  define i_sd_notifyf(unset, message, ...) \
	(void)sd_notifyf((unset), (message), __VA_ARGS__)
#else
#  define i_sd_notify(unset, message)
#  define i_sd_notifyf(unset, message, ...)
#endif

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DOVECOT_CONFIG_BIN_PATH BINDIR"/doveconf"

#define MASTER_SERVICE_NAME "master"
#define FATAL_FILENAME "master-fatal.lastlog"
#define MASTER_PID_FILE_NAME "master.pid"
#define SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_MSECS (60*3*1000)
#define SERVICE_TIME_MOVED_FORWARDS_MIN_WARNING_MSECS (200*1000)

struct master_delayed_error {
	enum log_type type;
	const char *line;
};

uid_t master_uid;
gid_t master_gid;
bool core_dumps_disabled;
bool have_proc_fs_suid_dumpable;
bool have_proc_sys_kernel_core_pattern;
const char *ssl_manual_key_password;
int global_master_dead_pipe_fd[2];
struct log_error_buffer *log_error_buffer;
int global_config_fd = -1;
struct service_list *services;
bool startup_finished = FALSE;

static char *pidfile_path;
static struct master_instance_list *instances;
static struct timeout *to_instance;

static ARRAY(struct master_delayed_error) delayed_errors;
static pool_t delayed_errors_pool;
static failure_callback_t *orig_fatal_callback;
static failure_callback_t *orig_error_callback;

void process_exec(const char *cmd)
{
	const char *executable, *p, **argv;

	argv = t_strsplit(cmd, " ");
	executable = argv[0];

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	/* prefix with dovecot/ */
	argv[0] = t_strdup_printf("%s/%s", services->set->instance_name,
				  argv[0]);
	if (!str_begins_with(argv[0], PACKAGE))
		argv[0] = t_strconcat(PACKAGE"-", argv[0], NULL);
	execv_const(executable, argv);
}

int get_uidgid(const char *user, uid_t *uid_r, gid_t *gid_r,
	       const char **error_r)
{
	struct passwd pw;

	if (*user == '\0') {
		*uid_r = (uid_t)-1;
		*gid_r = (gid_t)-1;
		return 0;
	}

	switch (i_getpwnam(user, &pw)) {
	case -1:
		*error_r = t_strdup_printf("getpwnam(%s) failed: %m", user);
		return -1;
	case 0:
		*error_r = t_strdup_printf("User doesn't exist: %s", user);
		return -1;
	default:
		*uid_r = pw.pw_uid;
		*gid_r = pw.pw_gid;
		return 0;
	}
}

int get_gid(const char *group, gid_t *gid_r, const char **error_r)
{
	struct group gr;

	if (*group == '\0') {
		*gid_r = (gid_t)-1;
		return 0;
	}

	switch (i_getgrnam(group, &gr)) {
	case -1:
		*error_r = t_strdup_printf("getgrnam(%s) failed: %m", group);
		return -1;
	case 0:
		*error_r = t_strdup_printf("Group doesn't exist: %s", group);
		return -1;
	default:
		*gid_r = gr.gr_gid;
		return 0;
	}
}

static void ATTR_FORMAT(2, 0)
master_error_handler(const struct failure_context *ctx,
		     const char *fmt, va_list args)
{
	va_list args2;

	VA_COPY(args2, args);
	struct log_error error = {
		.type = ctx->type,
		.timestamp = ioloop_timeval,
		.prefix = ctx->log_prefix != NULL ? ctx->log_prefix : "",
		.text = t_strdup_vprintf(fmt, args2),
	};
	log_error_buffer_add(log_error_buffer, &error);
	va_end(args2);

	orig_error_callback(ctx, fmt, args);
}

static void ATTR_NORETURN ATTR_FORMAT(2, 0)
master_fatal_callback(const struct failure_context *ctx,
		      const char *format, va_list args)
{
	const char *path, *str;
	va_list args2;
	pid_t pid;
	int fd;

	/* if we already forked a child process, this isn't fatal for the
	   main process and there's no need to write the fatal file. */
	if (str_to_pid(my_pid, &pid) < 0)
		i_unreached();
	if (getpid() == pid) {
		/* write the error message to a file (we're chdired to
		   base dir) */
		path = t_strconcat(FATAL_FILENAME, NULL);
		fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if (fd != -1) {
			VA_COPY(args2, args);
			str = t_strdup_vprintf(format, args2);
			va_end(args2);
			(void)write_full(fd, str, strlen(str));
			i_close_fd(&fd);
		}
	}

	orig_fatal_callback(ctx, format, args);
	abort(); /* just to silence the noreturn attribute warnings */
}

static void ATTR_NORETURN ATTR_FORMAT(2, 0)
startup_fatal_handler(const struct failure_context *ctx,
		      const char *fmt, va_list args)
{
	va_list args2;

	VA_COPY(args2, args);
	fprintf(stderr, "%s%s\n", failure_log_type_prefixes[ctx->type],
		t_strdup_vprintf(fmt, args2));
	va_end(args2);
	orig_fatal_callback(ctx, fmt, args);
	abort();
}

static void ATTR_FORMAT(2, 0)
startup_error_handler(const struct failure_context *ctx,
		      const char *fmt, va_list args)
{
	va_list args2;

	VA_COPY(args2, args);
	fprintf(stderr, "%s%s\n", failure_log_type_prefixes[ctx->type],
		t_strdup_vprintf(fmt, args2));
	va_end(args2);
	orig_error_callback(ctx, fmt, args);
}

static void ATTR_FORMAT(2, 0)
startup_early_error_handler(const struct failure_context *ctx,
			    const char *fmt, va_list args)
{
	struct master_delayed_error *err;
	va_list args2;

	VA_COPY(args2, args);
	if (delayed_errors_pool == NULL) {
		delayed_errors_pool =
			pool_alloconly_create("delayed errors", 512);
		i_array_init(&delayed_errors, 8);
	}
	err = array_append_space(&delayed_errors);
	err->type = ctx->type;
	err->line = p_strdup_vprintf(delayed_errors_pool, fmt, args2);
	va_end(args2);

	orig_error_callback(ctx, fmt, args);
}

static void startup_early_errors_flush(void)
{
	struct failure_context ctx;
	const struct master_delayed_error *err;

	if (delayed_errors_pool == NULL)
		return;

	i_zero(&ctx);
	array_foreach(&delayed_errors, err) {
		ctx.type = err->type;
		i_log_type(&ctx, "%s", err->line);
	}
	array_free(&delayed_errors);
	pool_unref(&delayed_errors_pool);
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

	ret = read(fd, buf, sizeof(buf)-1);
	if (ret < 0)
		i_error("read(%s) failed: %m", path);
	else {
		buf[ret] = '\0';
		fprintf(stderr, "Last died with error (see error log for more "
			"information): %s\n", buf);
	}

	i_close_fd(&fd);
	i_unlink(path);
}

static bool pid_file_read(const char *path, pid_t *pid_r)
{
	char buf[32];
	int fd;
	ssize_t ret;
	bool found;

	*pid_r = (pid_t)-1;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return FALSE;
		i_fatal("open(%s) failed: %m", path);
	}

	ret = read(fd, buf, sizeof(buf)-1);
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
		if (str_to_pid(buf, pid_r) < 0) {
			i_error("PID file contains invalid PID value");
			found = FALSE;
		} else {
			found = !(*pid_r == getpid() ||
				  (kill(*pid_r, 0) < 0 && errno == ESRCH));
		}
	}
	i_close_fd(&fd);
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
	i_close_fd(&fd);
}

static void create_config_symlink(const struct master_settings *set)
{
	const char *base_config_path;

	base_config_path = t_strconcat(set->base_dir, "/"PACKAGE".conf", NULL);
	i_unlink_if_exists(base_config_path);

	if (symlink(services->config->config_file_path, base_config_path) < 0) {
		i_error("symlink(%s, %s) failed: %m",
			services->config->config_file_path, base_config_path);
	}
}

static void instance_update_now(struct master_instance_list *list)
{
	int ret;

	ret = master_instance_list_set_name(list, services->set->base_dir,
					    services->set->instance_name);
	if (ret == 0) {
		/* duplicate instance names. allow without warning.. */
		(void)master_instance_list_update(list, services->set->base_dir);
	}

	timeout_remove(&to_instance);
	to_instance = timeout_add((3600 * 12 + i_rand_limit(60 * 30)) * 1000,
				  instance_update_now, list);
}

static void instance_update(const struct master_settings *set)
{
	const char *path;

	path = t_strconcat(set->state_dir, "/"MASTER_INSTANCE_FNAME, NULL);
	instances = master_instance_list_init(path);
	instance_update_now(instances);
}

static void
sig_settings_reload(const siginfo_t *si ATTR_UNUSED,
		    void *context ATTR_UNUSED)
{
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const struct master_settings *set;
	struct service_list *new_services;
	struct service *service;
	const char *error;

	i_sd_notify(0, "RELOADING=1");
	i_warning("SIGHUP received - reloading configuration");

	/* see if hostname changed */
	hostpid_init();

	if (services->config->process_avail == 0) {
		/* we can't reload config if there's no config process. */
		if (service_process_create(services->config, -1, NULL) == NULL) {
			i_error("Can't reload configuration because "
				"we couldn't create a config process");
			i_sd_notify(0, "READY=1");
			return;
		}
	}

	i_zero(&input);
	input.config_path = services_get_config_socket_path(services);
	input.no_service_filter = TRUE;
	input.never_exec = TRUE;
	input.reload_config = TRUE;
	input.return_config_fd = TRUE;
	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0) {
		i_error("%s", error);
		i_sd_notify(0, "READY=1");
		return;
	}
	if (settings_get(master_service_get_event(master_service),
			 &master_setting_parser_info, 0,
			 &set, &error) < 0) {
		i_close_fd(&output.config_fd);
		i_error("%s", error);
		i_sd_notify(0, "READY=1");
		return;
	}
	i_close_fd(&global_config_fd);
	global_config_fd = output.config_fd;
	fd_close_on_exec(global_config_fd, TRUE);

	if (services_create(set, &new_services, &error) < 0) {
		/* new configuration is invalid, keep the old */
		i_error("Config reload failed: %s", error);
		i_sd_notify(0, "READY=1");
		settings_free(set);
		return;
	}
	settings_free(set);
	new_services->config->config_file_path =
		p_strdup(new_services->pool,
			 services->config->config_file_path);

	/* switch to new configuration. */
	services_monitor_stop(services, FALSE);
	if (services_listen_using(new_services, services) < 0) {
		services_monitor_start(services);
		i_sd_notify(0, "READY=1");
		return;
	}

	/* anvil never dies. it just gets moved to the new services list */
	service = service_lookup_type(services, SERVICE_TYPE_ANVIL);
	if (service != NULL) {
		while (service->busy_processes != NULL)
			service_process_destroy(service->busy_processes);
		while (service->idle_processes_head != NULL)
			service_process_destroy(service->idle_processes_head);
	}
	services_destroy(services, FALSE);

	services = new_services;
        services_monitor_start(services);
	i_sd_notify(0, "READY=1");
}

static void
sig_log_reopen(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	unsigned int uninitialized_count;
	service_signal(services->log, SIGUSR1, &uninitialized_count);

	master_service->log_initialized = FALSE;
	master_service_init_log(master_service);
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
	/* make sure new processes won't be created by the currently
	   running ioloop. */
	services->destroying = TRUE;
	i_sd_notify(0, "STOPPING=1\nSTATUS=Dovecot stopping...");
	master_service_stop(master_service);
}

static const struct master_settings *master_settings_read(void)
{
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;

	i_zero(&input);
	input.no_service_filter = TRUE;
	input.preserve_environment = TRUE;
	input.check_full_config = TRUE;
	input.always_exec = TRUE;
	input.return_config_fd = TRUE;
	if (master_service_settings_read(master_service, &input, &output,
					 &error) < 0)
		i_fatal("%s", error);
	global_config_fd = output.config_fd;
	fd_close_on_exec(global_config_fd, TRUE);
	return settings_get_or_fatal(master_service_get_event(master_service),
				     &master_setting_parser_info);
}

static void main_log_startup(const char *const *protocols)
{
#define STARTUP_STRING PACKAGE_NAME" v"DOVECOT_VERSION_FULL" starting up"
	string_t *str = t_str_new(128);
	rlim_t core_limit;
	struct stat st;

	str_append(str, STARTUP_STRING);
	if (protocols[0] == NULL)
		str_append(str, " without any protocols");
	else {
		str_printfa(str, " for %s",
			    t_strarray_join(protocols, ", "));
	}

	core_dumps_disabled = restrict_get_core_limit(&core_limit) == 0 &&
		core_limit == 0;
	if (core_dumps_disabled)
		str_append(str, " (core dumps disabled)");
	if (stat(LINUX_PROC_FS_SUID_DUMPABLE, &st) == 0)
		have_proc_fs_suid_dumpable = TRUE;
	if (stat(LINUX_PROC_SYS_KERNEL_CORE_PATTERN, &st) == 0)
		have_proc_sys_kernel_core_pattern = TRUE;
	i_info("%s", str_c(str));
}

static void master_set_process_limit(void)
{
	struct service *service;
	unsigned int process_limit = 0;
	rlim_t nproc;

	/* we'll just count all the processes that can exist and set the
	   process limit so that we won't reach it. it's usually higher than
	   needed, since we'd only need to set it high enough for each
	   separate UID not to reach the limit, but this is difficult to
	   guess: mail processes should probably be counted together for a
	   common vmail user (unless system users are being used), but
	   we can't really guess what the mail processes are. */
	array_foreach_elem(&services->services, service)
		process_limit += service->process_limit;

	if (restrict_get_process_limit(&nproc) == 0 &&
	    process_limit > nproc)
		restrict_process_count(process_limit);
}

static void main_init(const struct master_settings *set)
{
	master_set_process_limit();
	drop_capabilities();

	/* deny file access from everyone else except owner */
        (void)umask(0077);

	main_log_startup(settings_boollist_get(&set->protocols));

	lib_signals_init();
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
	lib_signals_set_handler(SIGHUP, LIBSIG_FLAGS_SAFE,
				sig_settings_reload, NULL);
	lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
				sig_log_reopen, NULL);
	lib_signals_set_handler(SIGCHLD, LIBSIG_FLAGS_SAFE,
				sig_reap_children, NULL);
        lib_signals_set_handler(SIGINT, LIBSIG_FLAGS_SAFE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, LIBSIG_FLAGS_SAFE, sig_die, NULL);

	create_pid_file(pidfile_path);
	create_config_symlink(set);
	instance_update(set);
	master_clients_init();

	services_monitor_start(services);
	i_sd_notifyf(0, "READY=1\nSTATUS=v" DOVECOT_VERSION_FULL " running\n"
		   "MAINPID=%u", getpid());
	startup_finished = TRUE;
}

static void global_dead_pipe_close(void)
{
	if (close(global_master_dead_pipe_fd[0]) < 0)
		i_error("close(global dead pipe) failed: %m");
	if (close(global_master_dead_pipe_fd[1]) < 0)
		i_error("close(global dead pipe) failed: %m");
	global_master_dead_pipe_fd[0] = -1;
	global_master_dead_pipe_fd[1] = -1;
}

static void main_deinit(void)
{
	master_clients_deinit();
	instance_update_now(instances);
	timeout_remove(&to_instance);
	master_instance_list_deinit(&instances);

	/* kill services and wait for them to die before unlinking pid file */
	global_dead_pipe_close();
	services_destroy(services, TRUE);

	i_unlink(pidfile_path);
	i_free(pidfile_path);

	service_anvil_global_deinit();
	service_pids_deinit();
	/* notify systemd that we are done */
	i_sd_notify(0, "STATUS=Dovecot stopped");

	i_set_error_handler(orig_error_callback);
	log_error_buffer_deinit(&log_error_buffer);
}

static const char *get_full_config_path(struct service_list *list)
{
	const char *path;

	path = master_service_get_config_path(master_service);
	if (*path == '/')
		return path;

	const char *abspath, *error;
	if (t_abspath(path, &abspath, &error) < 0) {
		i_fatal("t_abspath(%s) failed: %s", path, error);
	}
	return p_strdup(list->pool, abspath);
}

static void
master_time_moved(const struct timeval *old_time,
		  const struct timeval *new_time)
{
	long long diff = timeval_diff_usecs(old_time, new_time);
	unsigned int msecs;

	if (diff < 0) {
		diff = -diff;
		if (diff < SERVICE_TIME_MOVED_FORWARDS_MIN_WARNING_MSECS) {
			i_info("Time moved forward by %lld.%06lld seconds - adjusting timeouts.",
			       diff / 1000000, diff % 1000000);
		} else {
			i_warning("Time moved forward by %lld.%06lld seconds - adjusting timeouts.",
				  diff / 1000000, diff % 1000000);
		}
		return;
	}
	msecs = (unsigned int)(diff/1000);

	/* time moved backwards. disable launching new service processes
	   until the throttling timeout has reached. */
	if (msecs > SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_MSECS)
		msecs = SERVICE_TIME_MOVED_BACKWARDS_MAX_THROTTLE_MSECS;
	services_throttle_time_sensitives(services, msecs);
	i_warning("Time moved backwards by %lld.%06lld seconds, waiting for "
		  "%u.%03u seconds until new services are launched again.",
		  diff / 1000000, diff % 1000000, msecs / 1000, msecs % 1000);
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
"       [--build-options] [--hostdomain] [reload] [stop]\n");
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
#ifdef IOLOOP_NOTIFY_INOTIFY
		" notify=inotify"
#endif
#ifdef IOLOOP_NOTIFY_KQUEUE
		" notify=kqueue"
#endif
#ifdef DOVECOT_PRO_EDITION
	        " pro"
#endif
#ifdef EXPERIMENTAL_IMAP4REV2
		" experimental-imap4rev2"
#endif
		" openssl"
	        " io_block_size=%u"
#ifdef SQL_DRIVER_PLUGINS
	"\nSQL driver plugins:"
#else
	"\nSQL drivers:"
#endif
#ifdef BUILD_CASSANDRA
		" cassandra"
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
#ifdef HAVE_LDAP
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
#ifdef PASSDB_SQL
		" sql"
#endif
	"\nUserdb:"
#ifdef HAVE_LDAP
		" ldap"
#ifndef BUILTIN_LDAP
		"(plugin)"
#endif
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
	"\n", IO_BLOCK_SIZE);
}

int main(int argc, char *argv[])
{
	const struct master_settings *set;
	const char *error, *doveconf_arg = NULL;
	failure_callback_t *orig_info_callback, *orig_debug_callback;
	bool foreground = FALSE, ask_key_pass = FALSE;
	bool doubleopts[argc];
	int i, c;

#ifdef DEBUG
	if (getenv("GDB") == NULL) {
		const char *config_fd_env = getenv(DOVECOT_CONFIG_FD_ENV);
		if (config_fd_env != NULL) {
			int config_fd;
			if (str_to_int(config_fd_env, &config_fd) < 0 ||
				       config_fd <= 3 || config_fd >= 1024) {
				i_fatal("'%s' is not valid number (in environment variable %s)",
					config_fd_env, DOVECOT_CONFIG_FD_ENV);
			}
			fd_debug_verify_leaks(3, config_fd - 1);
			fd_debug_verify_leaks(config_fd + 1, 1024);
		} else {
			fd_debug_verify_leaks(3, 1024);
		}
	}
#endif
	/* drop -- prefix from all --args. ugly, but the only way that it
	   works with standard getopt() in all OSes.. */
	for (i = 1; i < argc; i++) {
		if (str_begins_with(argv[i], "--")) {
			if (argv[i][2] == '\0')
				break;
			argv[i] += 2;
			doubleopts[i] = TRUE;
		} else {
			doubleopts[i] = FALSE;
		}
	}
	master_service = master_service_init(MASTER_SERVICE_NAME,
				MASTER_SERVICE_FLAG_STANDALONE |
				MASTER_SERVICE_FLAG_DONT_SEND_STATS |
				MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR |
				MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
				&argc, &argv, "+Fanp");
	i_unset_failure_prefix();

	i_get_failure_handlers(&orig_fatal_callback, &orig_error_callback,
			       &orig_info_callback, &orig_debug_callback);
	i_set_error_handler(startup_early_error_handler);

	io_loop_set_time_moved_callback(current_ioloop, master_time_moved);

	master_uid = geteuid();
	master_gid = getegid();

	while ((c = master_getopt(master_service)) > 0) {
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
				lib_exit(FATAL_DEFAULT);
			}
			break;
		}
	}
	i_assert(optind > 0 && optind <= argc);

	if (doveconf_arg != NULL) {
		const char **args;

		args = t_new(const char *, 5);
		args[0] = DOVECOT_CONFIG_BIN_PATH;
		args[1] = doveconf_arg;
		args[2] = "-c";
		args[3] = master_service_get_config_path(master_service);
		args[4] = NULL;
		execv_const(args[0], args);
	}

	if (optind == argc) {
		/* starting Dovecot */
	} else if (!doubleopts[optind]) {
		/* dovecot xx -> doveadm xx */
		(void)execv(BINDIR"/doveadm", argv);
		i_fatal("execv("BINDIR"/doveadm) failed: %m");
	} else if (strcmp(argv[optind], "version") == 0) {
		printf("%s\n", DOVECOT_VERSION_FULL);
		return 0;
	} else if (strcmp(argv[optind], "hostdomain") == 0) {
		printf("%s\n", my_hostdomain());
		return 0;
	} else if (strcmp(argv[optind], "build-options") == 0) {
		print_build_options();
		return 0;
	} else if (strcmp(argv[optind], "log-error") == 0) {
		fprintf(stderr, "Writing to error logs and killing myself..\n");
		argv[optind] = "log test";
		(void)execv(BINDIR"/doveadm", argv);
		i_fatal("execv("BINDIR"/doveadm) failed: %m");
	} else if (strcmp(argv[optind], "help") == 0) {
		print_help();
		return 0;
	} else {
		print_help();
		i_fatal("Unknown argument: --%s", argv[optind]);
	}

	if (pipe(global_master_dead_pipe_fd) < 0)
		i_fatal("pipe() failed: %m");
	fd_close_on_exec(global_master_dead_pipe_fd[0], TRUE);
	fd_close_on_exec(global_master_dead_pipe_fd[1], TRUE);

	set = master_settings_read();
	if (ask_key_pass) {
		ssl_manual_key_password =
			t_askpass("Give the password for SSL keys: ");
	}

	pidfile_path =
		i_strconcat(set->base_dir, "/"MASTER_PID_FILE_NAME, NULL);

	lib_set_clean_exit(TRUE);
	master_service_init_log(master_service);

	if (dup2(dev_null_fd, STDIN_FILENO) < 0)
		i_fatal("dup2(dev_null_fd) failed: %m");
	if (!i_failure_have_stdout_logs() &&
	    dup2(dev_null_fd, STDOUT_FILENO) < 0)
		i_fatal("dup2(dev_null_fd) failed: %m");

	startup_early_errors_flush();
	i_get_failure_handlers(&orig_fatal_callback, &orig_error_callback,
			       &orig_info_callback, &orig_debug_callback);
	i_set_fatal_handler(startup_fatal_handler);
	i_set_error_handler(startup_error_handler);

	pid_file_check_running(pidfile_path);
	master_settings_do_fixes(set);
	fatal_log_check(set);

	const char *import_environment =
		master_service_get_import_environment_keyvals(master_service);
	master_service_import_environment(import_environment);
	master_service_env_clean();

	/* create service structures from settings. if there are any errors in
	   service configuration we'll catch it here. */
	service_pids_init();
	service_anvil_global_init();
	if (services_create(set, &services, &error) < 0)
		i_fatal("%s", error);

	services->config->config_file_path = get_full_config_path(services);

	/* if any listening fails, fail completely */
	if (services_listen(services) <= 0)
		i_fatal("Failed to start listeners");

	if (chdir(set->base_dir) < 0)
		i_fatal("chdir(%s) failed: %m", set->base_dir);

	log_error_buffer = log_error_buffer_init();
	i_set_fatal_handler(master_fatal_callback);
	i_set_error_handler(master_error_handler);

	if (!foreground)
		daemonize();

	T_BEGIN {
		main_init(set);
		settings_free(set);
	} T_END;
	master_service_run(master_service, NULL);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
