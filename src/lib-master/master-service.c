/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "ioloop.h"
#include "hostpid.h"
#include "path-util.h"
#include "net.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "env-util.h"
#include "home-expand.h"
#include "process-title.h"
#include "time-util.h"
#include "restrict-access.h"
#include "settings-parser.h"
#include "syslog-util.h"
#include "stats-client.h"
#include "master-admin-client.h"
#include "master-instance.h"
#include "master-login.h"
#include "master-service-ssl.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "iostream-ssl.h"

#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>

#define DEFAULT_CONFIG_FILE_PATH SYSCONFDIR"/dovecot.conf"

/* getenv(MASTER_CONFIG_FILE_ENV) provides path to configuration file/socket */
#define MASTER_CONFIG_FILE_ENV "CONFIG_FILE"

/* getenv(MASTER_DOVECOT_VERSION_ENV) provides master's version number */
#define MASTER_DOVECOT_VERSION_ENV "DOVECOT_VERSION"

/* when we're full of connections, how often to check if login state has
   changed. we normally notice it immediately because of a signal, so this is
   just a fallback against race conditions. */
#define MASTER_SERVICE_STATE_CHECK_MSECS 1000

/* If die callback hasn't managed to stop the service for this many seconds,
   force it. */
#define MASTER_SERVICE_DIE_TIMEOUT_MSECS (30*1000)

struct master_service *master_service;

static struct event_category master_service_category = {
	.name = NULL, /* set dynamically later */
};
static char *master_service_category_name;

static void master_service_io_listeners_close(struct master_service *service);
static int master_service_get_login_state(enum master_login_state *state_r);
static void master_service_refresh_login_state(struct master_service *service);
static void
master_status_send(struct master_service *service, bool important_update);

const char *master_service_getopt_string(void)
{
	return "c:i:ko:OL";
}

static int block_sigterm(sigset_t *oldmask_r)
{
	sigset_t sigmask;

	if (sigemptyset(&sigmask) < 0)
		i_error("sigemptyset() failed: %m");
	else if (sigaddset(&sigmask, SIGTERM) < 0)
		i_error("sigaddset(SIGTERM) failed: %m");
	else if (sigprocmask(SIG_BLOCK, &sigmask, oldmask_r) < 0)
		i_error("sigprocmask(SIG_BLOCK, SIGTERM) failed: %m");
	else
		return 0;
	return -1;
}

static void
log_killed_signal(struct master_service *service, const siginfo_t *si)
{
	if (service->killed_signal_logged)
		return;

	i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
		  si->si_signo, dec2str(si->si_pid), dec2str(si->si_uid),
		  lib_signal_code_to_str(si->si_signo, si->si_code));
	service->killed_signal_logged = TRUE;
}

static void sig_delayed_die(const siginfo_t *si, void *context)
{
	struct master_service *service = context;

	/* SIGINT comes either from master process or from keyboard. we don't
	   want to log it in either case.*/
	if (si->si_signo != SIGINT) {
		log_killed_signal(service, si);
	} else if ((service->flags & MASTER_SERVICE_FLAG_NO_IDLE_DIE) != 0) {
		/* never die when idling */
		return;
	} else if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		/* SIGINT came from master. die only if we're not handling
		   any clients currently. */
		if (service->master_status.available_count !=
		    service->total_available_count)
			return;

		if (service->idle_die_callback != NULL &&
		    !service->idle_die_callback()) {
			/* we don't want to die - send a notification to master
			   so it doesn't think we're ignoring it completely. */
			master_status_send(service, FALSE);
			return;
		}
	}

	service->killed_signal = si->si_signo;
	io_loop_stop(service->ioloop);
}

static bool sig_term_buf_get_kick_user(char *buf, const char **user_r)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	if (strncmp(buf, "VERSION\tmaster-admin-client\t1\t", 30) != 0)
		return FALSE;
	buf += 30;
	/* skip over minor version */
	while (*buf >= '0' && *buf <= '0') buf++;
	if (*buf != '\n')
		return FALSE;
	buf++;

	if (strncmp(buf, "KICK-USER-SIGNAL\t", 17) != 0)
		return FALSE;
	buf += 17;

	/* <user> [<conn-guid>] - Handling the conn-guid is too much effort,
	   it should normally be enough to just check the user. */
	char *p = strpbrk(buf, "\t\n");
	if (p == NULL)
		return FALSE;
	*p = '\0';

	*user_r = buf;
	return TRUE;
}

static bool
sig_service_kick_user_match(struct master_service *service, const char *user)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	if (service->current_user != NULL)
		return strcmp(user, service->current_user) == 0 ? 1 : 0;
	else {
		/* There is no currently accessed user. Most likely it
		   means that the process already stopped handling the
		   requested user. */
		return 0;
	}
}

static int sig_term_try_kick_user(struct master_service *service, int fd_listen)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	int fd, ret = -1;
	char buf[256];
	ssize_t bytes;

	if (service->last_kick_signal_user != NULL &&
	    service->last_kick_signal_user_accessed == 0) {
		/* The signal came a bit late. The KICK-USER-SIGNAL command
		   was already handled. */
		service->last_kick_signal_user_accessed = 1;
		return sig_service_kick_user_match(service,
			service->last_kick_signal_user) ? 1 : 0;
	}

	fd = accept(fd_listen, NULL, NULL);
	if (fd < 0) {
		if (errno == EAGAIN || errno == ECONNABORTED)
			return -1;
		lib_signals_syscall_error("SIGTERM: accept() failed: ");
		return -1;
	}
	alarm(1);
	bytes = read(fd, buf, sizeof(buf)-1);
	alarm(0);
	if (bytes >= 0) {
		const char *user;
		buf[bytes] = '\0';
		if (!sig_term_buf_get_kick_user(buf, &user)) {
			/* This wasn't a KICK-USER-SIGNAL command at all. The
			   process will be soon killed with a delayed SIGTERM,
			   so we can simply close the connection and ignore the
			   command. */
		} else {
			ret = sig_service_kick_user_match(service, user) ? 1 : 0;
		}
	} else if (errno != EINTR) {
		lib_signals_syscall_error("SIGTERM: read() failed: ");
	}
	if (close(fd) < 0)
		lib_signals_syscall_error("SIGTERM: close() failed: ");
	return ret;
}

static bool sig_term_try_kick(struct master_service *service)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	int ret;

	/* see if there's a admin-socket connection waiting */
	for (unsigned int i = 0; i < service->socket_count; i++) {
		struct master_service_listener *l = &service->listeners[i];

		if (master_admin_client_can_accept(l->name)) {
			ret = sig_term_try_kick_user(service, l->fd);
			if (ret > 0) {
				/* USER-KICK matched */
				return TRUE;
			}
			if (ret == 0) {
				/* USER-KICK mismatch - ignore */
				return FALSE;
			}
			/* no connection or not a USER-KICK command */
		}
	}
	/* no. just handle the signal normally as a delayed signal. */
	return TRUE;
}

static void sig_die_delayed(struct master_service *service, const siginfo_t *si)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	if (service->killed_time.tv_sec == 0) {
#ifdef HAVE_CLOCK_GETTIME
		struct timespec ts;
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
			lib_signals_syscall_error("clock_gettime() failed: ");
			service->killed_time.tv_sec = time(NULL);
			service->killed_time.tv_usec = 0;
		} else {
			service->killed_time.tv_sec = ts.tv_sec;
			service->killed_time.tv_usec = ts.tv_nsec/1000;
		}
#else
		service->killed_time.tv_sec = time(NULL);
		service->killed_time.tv_usec = 0;
#endif
	}
	service->killed_signal_info = *si;
	/* set killed_signal after killed_time */
	service->killed_signal = si->si_signo;
	lib_signal_delayed(si);
}

static void sig_standalone_die(const siginfo_t *si, void *context)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	struct master_service *service = context;

	sig_die_delayed(service, si);
}

static void sig_term(const siginfo_t *si, void *context)
{
	/* WARNING: We are in a (non-delayed) signal handler context.
	   Be VERY careful what functions you call. */
	struct master_service *service = context;
	sigset_t sigmask, oldmask;
	int saved_errno = errno;
	bool call_delayed = TRUE;

	/* Block SIGTERM so that we don't get back here recursively. */
	if (sigemptyset(&sigmask) < 0)
		lib_signals_syscall_error("SIGTERM: sigemptyset() failed: ");
	else if (sigaddset(&sigmask, SIGTERM) < 0)
		lib_signals_syscall_error("SIGTERM: sigaddset() failed: ");
	else if (sigprocmask(SIG_BLOCK, &sigmask, &oldmask) < 0)
		lib_signals_syscall_error("SIGTERM: sigprocmask(SIG_BLOCK) failed: ");
	else {
		call_delayed = sig_term_try_kick(service);
		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
			lib_signals_syscall_error("SIGTERM: sigprocmask(SIG_SETMASK) failed: ");
	}

	if (call_delayed)
		sig_die_delayed(service, si);
	errno = saved_errno;
}

static void sig_close_listeners(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct master_service *service = context;

	/* We're in a signal handler: Close listeners immediately so master
	   can successfully restart. We can safely close only those listeners
	   that don't have an io, but this shouldn't be a big problem. If there
	   is an active io, the service is unlikely to be unresposive for
	   longer periods of time, so the listener gets closed soon enough via
	   master_status_error().

	   For extra safety we don't actually close() the fd, but instead
	   replace it with /dev/null. This way it won't be replaced with some
	   other new fd and attempted to be used in unexpected ways. */
	for (unsigned int i = 0; i < service->socket_count; i++) {
		if (service->listeners[i].fd != -1 &&
		    service->listeners[i].io == NULL) {
			if (dup2(dev_null_fd, service->listeners[i].fd) < 0)
				lib_signals_syscall_error("signal: dup2(/dev/null, listener) failed: ");
			service->listeners[i].closed = TRUE;
		}
	}
}

static void
sig_delayed_state_changed(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct master_service *service = context;

	master_service_refresh_login_state(service);
}

static bool
master_service_event_callback(struct event *event,
			      enum event_callback_type type,
			      struct failure_context *ctx,
			      const char *fmt ATTR_UNUSED,
			      va_list args ATTR_UNUSED)
{
	if (type == EVENT_CALLBACK_TYPE_CREATE && event->parent == NULL) {
		/* Add service:<name> category for all events. It's enough
		   to do it only for root events, because all other events
		   inherit the category from them. */
		event_add_category(event, &master_service_category);
	}
	/* This callback may be called while still in master_service_init().
	   In that case master_service is NULL. */
	if (type == EVENT_CALLBACK_TYPE_SEND && master_service != NULL &&
	    event_filter_match(master_service->process_shutdown_filter,
			       event, ctx))
		master_service_stop_new_connections(master_service);
	return TRUE;
}

static void master_service_verify_version_string(struct master_service *service)
{
	if (service->version_string != NULL &&
	    strcmp(service->version_string, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, %s is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)",
			service->version_string, service->name);
	}
}

static void master_service_init_socket_listeners(struct master_service *service)
{
	unsigned int i;
	const char *value;
	bool have_ssl_sockets = FALSE;

	if (service->socket_count == 0)
		return;

	service->listeners =
		i_new(struct master_service_listener, service->socket_count);

	for (i = 0; i < service->socket_count; i++) {
		struct master_service_listener *l = &service->listeners[i];

		l->service = service;
		l->fd = MASTER_LISTEN_FD_FIRST + i;

		value = getenv(t_strdup_printf("SOCKET%u_SETTINGS", i));
		if (value != NULL) {
			const char *const *settings =
				t_strsplit_tabescaped(value);

			if (*settings != NULL) {
				l->name = i_strdup_empty(*settings);
				if (master_admin_client_can_accept(l->name))
					service->have_admin_sockets = TRUE;
				settings++;
			}
			while (*settings != NULL) {
				if (strcmp(*settings, "ssl") == 0) {
					l->ssl = TRUE;
					have_ssl_sockets = TRUE;
				} else if (strcmp(*settings, "haproxy") == 0) {
					l->haproxy = TRUE;
				}
				settings++;
			}
		}
	}
	service->want_ssl_server = have_ssl_sockets ||
		(service->flags & MASTER_SERVICE_FLAG_HAVE_STARTTLS) != 0;
}

struct master_service *
master_service_init(const char *name, enum master_service_flags flags,
		    int *argc, char **argv[], const char *getopt_str)
{
	struct master_service *service;
	data_stack_frame_t datastack_frame_id = 0;
	unsigned int count;
	const char *service_configured_name, *value;

	i_assert(name != NULL);

#ifdef DEBUG
	if (getenv("GDB") == NULL &&
	    (flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		value = getenv("SOCKET_COUNT");
		if (value == NULL || str_to_uint(value, &count) < 0)
			count = 0;
		fd_debug_verify_leaks(MASTER_LISTEN_FD_FIRST + count, 1024);
	}
#endif
	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		/* make sure we can dump core, at least until
		   privileges are dropped. (i'm not really sure why this
		   is needed, because doing the same just before exec
		   doesn't help, and exec shouldn't affect this with
		   non-setuid/gid binaries..) */
		restrict_access_allow_coredumps(TRUE);
	}

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	/* Get the service name from environment. This usually differs from the
	   service name parameter if the executable is used for multiple
	   services. For example "auth" vs "auth-worker". It can also be a
	   service with slightly different settings, like "lmtp" vs
	   "lmtp-no-quota". We don't want to use the configured name as the
	   service's primary name, because that could break some lookups (e.g.
	   auth would suddenly see service=lmtp-no-quota. However, this can be
	   very useful in events to differentiate e.g. auth master and
	   auth-worker events which might otherwise look very similar. It's
	   also useful in log prefixes. */
	service_configured_name = getenv(MASTER_SERVICE_ENV);
	if (service_configured_name == NULL)
		service_configured_name = name;
	/* Set a logging prefix temporarily. This will be ignored once the log
	   is properly initialized */
	i_set_failure_prefix("%s(init): ", service_configured_name);

	/* make sure all the data stack allocations during init will be freed
	   before we get to ioloop. the corresponding t_pop() is in
	   master_service_init_finish(). */
	if ((flags & MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME) == 0)
		datastack_frame_id = t_push("master_service_init");

	/* ignore these signals as early as possible */
	lib_signals_init();
	lib_signals_ignore(SIGPIPE, TRUE);
	lib_signals_ignore(SIGALRM, FALSE);

	if (getenv(MASTER_UID_ENV) == NULL)
		flags |= MASTER_SERVICE_FLAG_STANDALONE;

	process_title_init(*argc, argv);

	/* process_title_init() might destroy all environments.
	   Need to look this up again. */
	service_configured_name = getenv(MASTER_SERVICE_ENV);
	if (service_configured_name == NULL)
		service_configured_name = name;

	service = i_new(struct master_service, 1);
	service->argc = *argc;
	service->argv = *argv;
	service->name = i_strdup(name);
	service->configured_name = i_strdup(service_configured_name);
	/* keep getopt_str first in case it contains "+" */
	service->getopt_str = *getopt_str == '\0' ?
		i_strdup(master_service_getopt_string()) :
		i_strconcat(getopt_str, master_service_getopt_string(), NULL);
	service->flags = flags;
	service->ioloop = io_loop_create();
	service->service_count_left = UINT_MAX;
	service->config_fd = -1;
	service->datastack_frame_id = datastack_frame_id;

	service->config_path = i_strdup(getenv(MASTER_CONFIG_FILE_ENV));
	if (service->config_path == NULL)
		service->config_path = i_strdup(DEFAULT_CONFIG_FILE_PATH);
	else
		service->config_path_from_master = TRUE;

	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		service->version_string = getenv(MASTER_DOVECOT_VERSION_ENV);
		service->socket_count = 1;
	} else {
		service->version_string = PACKAGE_VERSION;
	}

	/* listener configuration */
	value = getenv("SOCKET_COUNT");
	if (value != NULL && str_to_uint(value, &service->socket_count) < 0)
		i_fatal("Invalid SOCKET_COUNT environment");
	T_BEGIN {
		master_service_init_socket_listeners(service);
	} T_END;

#ifdef HAVE_SSL
	/* Load the SSL module if we already know it is necessary. It can also
	   get loaded later on-demand. */
	if (service->want_ssl_server) {
		const char *error;
		if (ssl_module_load(&error) < 0)
			i_fatal("Cannot load SSL module: %s", error);
	}
#endif

	/* set up some kind of logging until we know exactly how and where
	   we want to log */
	if (getenv("LOG_SERVICE") != NULL)
		i_set_failure_internal();
	if (getenv("USER") != NULL) {
		i_set_failure_prefix("%s(%s): ", service->configured_name,
				     getenv("USER"));
	} else {
		i_set_failure_prefix("%s: ", service->configured_name);
	}

	master_service_category_name =
		i_strdup_printf("service:%s", service->configured_name);
	master_service_category.name = master_service_category_name;
	event_register_callback(master_service_event_callback);

	/* Initialize debug logging */
	value = getenv(DOVECOT_LOG_DEBUG_ENV);
	if (value != NULL) {
		struct event_filter *filter;
		const char *error;
		filter = event_filter_create();
		if (event_filter_parse(value, filter, &error) < 0) {
			i_error("Invalid "DOVECOT_LOG_DEBUG_ENV" - ignoring: %s",
				error);
		} else {
			event_set_global_debug_log_filter(filter);
		}
		event_filter_unref(&filter);
	}

	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		/* initialize master_status structure */
		value = getenv(MASTER_UID_ENV);
		if (value == NULL ||
		    str_to_uint(value, &service->master_status.uid) < 0)
			i_fatal(MASTER_UID_ENV" missing");
		service->master_status.pid = getpid();

		/* set the default limit */
		value = getenv(MASTER_CLIENT_LIMIT_ENV);
		if (value == NULL || str_to_uint(value, &count) < 0 ||
		    count == 0)
			i_fatal(MASTER_CLIENT_LIMIT_ENV" missing");
		master_service_set_client_limit(service, count);

		/* save the process limit */
		value = getenv(MASTER_PROCESS_LIMIT_ENV);
		if (value != NULL && str_to_uint(value, &count) == 0 &&
		    count > 0)
			service->process_limit = count;

		value = getenv(MASTER_PROCESS_MIN_AVAIL_ENV);
		if (value != NULL && str_to_uint(value, &count) == 0 &&
		    count > 0)
			service->process_min_avail = count;

		/* set the default service count */
		value = getenv(MASTER_SERVICE_COUNT_ENV);
		if (value != NULL && str_to_uint(value, &count) == 0 &&
		    count > 0)
			master_service_set_service_count(service, count);

		/* set the idle kill timeout */
		value = getenv(MASTER_SERVICE_IDLE_KILL_ENV);
		if (value != NULL && str_to_uint(value, &count) == 0)
			service->idle_kill_secs = count;
	} else {
		master_service_set_client_limit(service, 1);
		master_service_set_service_count(service, 1);
	}
	if ((flags & MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN) != 0) {
		/* since we're going to keep the config socket open anyway,
		   open it now so we can read settings even after privileges
		   are dropped. */
		master_service_config_socket_try_open(service);
	}
	if ((flags & MASTER_SERVICE_FLAG_DONT_SEND_STATS) == 0) {
		/* Initialize stats-client early so it can see all events. */
		value = getenv(DOVECOT_STATS_WRITER_SOCKET_PATH);
		if (value != NULL && value[0] != '\0')
			service->stats_client = stats_client_init(value, FALSE);
	}

	master_service_verify_version_string(service);
	return service;
}

int master_getopt(struct master_service *service)
{
	int c;

	i_assert(master_getopt_str_is_valid(service->getopt_str));

	while ((c = getopt(service->argc, service->argv,
			   service->getopt_str)) > 0) {
		if (!master_service_parse_option(service, c, optarg))
			break;
	}
	return c;
}

bool master_getopt_str_is_valid(const char *str)
{
	unsigned int i, j;

	/* make sure there are no duplicates. there are few enough characters
	   that this should be fast enough. */
	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] == ':' || str[i] == '+' || str[i] == '-')
			continue;
		for (j = i+1; str[j] != '\0'; j++) {
			if (str[i] == str[j])
				return FALSE;
		}
	}
	return TRUE;
}

static bool
master_service_try_init_log(struct master_service *service,
			    const char *prefix)
{
	const char *path, *timestamp;

	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0 &&
	    (service->flags & MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR) == 0) {
		timestamp = getenv("LOG_STDERR_TIMESTAMP");
		if (timestamp != NULL)
			i_set_failure_timestamp_format(timestamp);
		i_set_failure_file("/dev/stderr", "");
		return TRUE;
	}

	if (getenv("LOG_SERVICE") != NULL && !service->log_directly) {
		/* logging via log service */
		i_set_failure_internal();
		i_set_failure_prefix("%s", prefix);
		return TRUE;
	}

	if (service->set == NULL) {
		i_set_failure_file("/dev/stderr", prefix);
		/* may be called again after we have settings */
		return FALSE;
	}

	if (strcmp(service->set->log_path, "syslog") != 0) {
		/* error logging goes to file or stderr */
		path = home_expand(service->set->log_path);
		i_set_failure_file(path, prefix);
	}

	if (strcmp(service->set->log_path, "syslog") == 0 ||
	    strcmp(service->set->info_log_path, "syslog") == 0 ||
	    strcmp(service->set->debug_log_path, "syslog") == 0) {
		/* something gets logged to syslog */
		int facility;

		if (!syslog_facility_find(service->set->syslog_facility,
					  &facility))
			facility = LOG_MAIL;
		i_set_failure_syslog(service->set->instance_name, LOG_NDELAY,
				     facility);
		i_set_failure_prefix("%s", prefix);

		if (strcmp(service->set->log_path, "syslog") != 0) {
			/* set error handlers back to file */
			i_set_fatal_handler(default_fatal_handler);
			i_set_error_handler(default_error_handler);
		}
	}

	if (*service->set->info_log_path != '\0' &&
	    strcmp(service->set->info_log_path, "syslog") != 0) {
		path = home_expand(service->set->info_log_path);
		if (*path != '\0')
			i_set_info_file(path);
	}

	if (*service->set->debug_log_path != '\0' &&
	    strcmp(service->set->debug_log_path, "syslog") != 0) {
		path = home_expand(service->set->debug_log_path);
		if (*path != '\0')
			i_set_debug_file(path);
	}
	i_set_failure_timestamp_format(service->set->log_timestamp);
	return TRUE;
}

void master_service_init_log(struct master_service *service)
{
	master_service_init_log_with_prefix(service, t_strdup_printf(
		"%s: ", service->configured_name));
}

void master_service_init_log_with_prefix(struct master_service *service,
					 const char *prefix)
{
	if (service->log_initialized) {
		/* change only the prefix */
		i_set_failure_prefix("%s", prefix);
		return;
	}
	if (master_service_try_init_log(service, prefix))
		service->log_initialized = TRUE;
}

void master_service_init_log_with_pid(struct master_service *service)
{
	master_service_init_log_with_prefix(service, t_strdup_printf(
		"%s(%s): ", service->configured_name, my_pid));
}

void master_service_init_stats_client(struct master_service *service,
				      bool silent_notfound_errors)
{
	if (service->stats_client == NULL &&
	    service->set->stats_writer_socket_path[0] != '\0') T_BEGIN {
		const char *path = t_strdup_printf("%s/%s",
			service->set->base_dir,
			service->set->stats_writer_socket_path);
		service->stats_client =
			stats_client_init(path, silent_notfound_errors);
	} T_END;
}

void master_service_set_die_with_master(struct master_service *service,
					bool set)
{
	service->die_with_master = set;
}

void master_service_set_die_callback(struct master_service *service,
				     void (*callback)(void))
{
	service->die_callback = callback;
}

void master_service_set_idle_die_callback(struct master_service *service,
					  bool (*callback)(void))
{
	service->idle_die_callback = callback;
}

static bool get_instance_config(const char *name, const char **config_path_r)
{
	struct master_instance_list *list;
	const struct master_instance *inst;
	const char *instance_path, *path;

	/* note that we don't have any settings yet. we're just finding out
	   which dovecot.conf we even want to read! so we must use the
	   hardcoded state_dir path. */
	instance_path = t_strconcat(PKG_STATEDIR"/"MASTER_INSTANCE_FNAME, NULL);
	list = master_instance_list_init(instance_path);
	inst = master_instance_list_find_by_name(list, name);
	if (inst != NULL) {
		path = t_strdup_printf("%s/dovecot.conf", inst->base_dir);
		const char *error;
		if (t_readlink(path, config_path_r, &error) < 0)
			i_fatal("t_readlink(%s) failed: %s", path, error);
	}
	master_instance_list_deinit(&list);
	return inst != NULL;
}

bool master_service_parse_option(struct master_service *service,
				 int opt, const char *arg)
{
	const char *path;

	switch (opt) {
	case 'c':
		i_free(service->config_path);
		service->config_path = i_strdup(arg);
		service->config_path_changed_with_param = TRUE;
		service->config_path_from_master = FALSE;
		break;
	case 'i':
		if (!get_instance_config(arg, &path))
			i_fatal("Unknown instance name: %s", arg);
		service->config_path = i_strdup(path);
		service->config_path_changed_with_param = TRUE;
		break;
	case 'k':
		service->keep_environment = TRUE;
		break;
	case 'o':
		if (!array_is_created(&service->config_overrides))
			i_array_init(&service->config_overrides, 16);
		array_push_back(&service->config_overrides, &arg);
		break;
	case 'O':
		service->flags |= MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS;
		break;
	case 'L':
		service->log_directly = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static void master_service_error(struct master_service *service)
{
	/* Close all master-admin connections from anvil. This way they won't
	   block stopping the process quickly. */
	master_admin_clients_deinit();

	master_service_stop_new_connections(service);
	if (service->master_status.available_count ==
	    service->total_available_count || service->die_with_master) {
		if (service->die_callback == NULL)
			master_service_stop(service);
		else {
			service->to_die =
				timeout_add(MASTER_SERVICE_DIE_TIMEOUT_MSECS,
					    master_service_stop,
					    service);
			service->die_callback();
		}
	}
}

static void master_status_error(struct master_service *service)
{
	/* status fd is a write-only pipe, so if we're here it means the
	   master wants us to die (or died itself). don't die until all
	   service connections are finished. */
	io_remove(&service->io_status_error);

	/* the log fd may also be closed already, don't die when trying to
	   log later */
	i_set_failure_ignore_errors(TRUE);

	master_service_error(service);
}

static void master_status_update_wait(struct master_service *service)
{
	struct ioloop *ioloop = io_loop_create();
	service->io_status_waiting = TRUE;
	service->io_status_write = io_loop_move_io(&service->io_status_write);
	while (service->io_status_write != NULL)
		io_loop_run(ioloop);
	service->io_status_waiting = FALSE;
	io_loop_destroy(&ioloop);
}

void master_service_init_finish(struct master_service *service)
{
	struct stat st;

	i_assert(!service->init_finished);
	service->init_finished = TRUE;

	/* From now on we'll abort() if exit() is called unexpectedly. */
	lib_set_clean_exit(FALSE);

	/* set default signal handlers */
	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0) {
		/* Standalone programs stop immediately on signals */
		lib_signals_set_handler2(SIGINT, 0, sig_standalone_die,
					 sig_delayed_die, service);
		lib_signals_set_handler2(SIGTERM, 0, sig_standalone_die,
					 sig_delayed_die, service);
	} else {
		/* SIGINT is used by master for killing idle processes */
		lib_signals_set_handler(SIGINT, LIBSIG_FLAGS_SAFE,
					sig_delayed_die, service);
		if (!service->have_admin_sockets) {
			lib_signals_set_handler(SIGTERM, LIBSIG_FLAG_DELAYED,
						sig_delayed_die, service);
		} else {
			lib_signals_set_handler2(SIGTERM, 0, sig_term,
						 sig_delayed_die, service);
		}
	}
	if ((service->flags & MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE) != 0) {
		lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
					sig_delayed_state_changed, service);
	}

	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) == 0) {
		if (fstat(MASTER_STATUS_FD, &st) < 0 || !S_ISFIFO(st.st_mode))
			i_fatal("Must be started by dovecot master process");

		/* start listening errors for status fd, it means master died */
		service->io_status_error = io_add(MASTER_DEAD_FD, IO_ERROR,
						  master_status_error, service);
		lib_signals_set_handler(SIGQUIT, 0, sig_close_listeners, service);
	}
	master_service_io_listeners_add(service);
	if (service->want_ssl_server &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_SSL_INIT) == 0)
		master_service_ssl_ctx_init(service);

	if ((service->flags & MASTER_SERVICE_FLAG_STD_CLIENT) != 0) {
		/* we already have a connection to be served */
		service->master_status.available_count--;
	}
	master_status_update(service);
	if (service->io_status_write != NULL)
		master_status_update_wait(service);

	/* close data stack frame opened by master_service_init() */
	if ((service->flags & MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME) == 0) {
		if (!t_pop(&service->datastack_frame_id))
			i_panic("Leaked t_pop() call");
	}
}

static void master_service_import_environment_real(const char *import_environment)
{
	const char *const *envs, *key, *value;
	ARRAY_TYPE(const_string) keys;

	if (*import_environment == '\0')
		return;

	t_array_init(&keys, 8);
	/* preserve existing DOVECOT_PRESERVE_ENVS */
	value = getenv(DOVECOT_PRESERVE_ENVS_ENV);
	if (value != NULL)
		array_push_back(&keys, &value);
#ifdef HAVE_LIBSYSTEMD
	/* Always import systemd variables, otherwise it is possible to break
	   systemd startup in obscure ways. */
	value = "NOTIFY_SOCKET LISTEN_FDS LISTEN_PID";
	array_push_back(&keys, &value);
#endif
	/* add new environments */
	envs = t_strsplit_spaces(import_environment, " ");
	for (; *envs != NULL; envs++) {
		value = strchr(*envs, '=');
		if (value == NULL)
			key = *envs;
		else {
			key = t_strdup_until(*envs, value++);
			env_put(key, value);
		}
		array_push_back(&keys, &key);
	}
	array_append_zero(&keys);

	value = t_strarray_join(array_front(&keys), " ");
	env_put(DOVECOT_PRESERVE_ENVS_ENV, value);
}

void master_service_import_environment(const char *import_environment)
{
	T_BEGIN {
		master_service_import_environment_real(import_environment);
	} T_END;
}

void master_service_env_clean(void)
{
	const char *value = getenv(DOVECOT_PRESERVE_ENVS_ENV);

	if (value == NULL || *value == '\0')
		env_clean();
	else T_BEGIN {
		value = t_strconcat(value, " "DOVECOT_PRESERVE_ENVS_ENV, NULL);
		env_clean_except(t_strsplit_spaces(value, " "));
	} T_END;
}

void master_service_set_client_limit(struct master_service *service,
				     unsigned int client_limit)
{
	unsigned int used;

	i_assert(service->master_status.available_count ==
		 service->total_available_count);

	used = service->total_available_count -
		service->master_status.available_count;
	i_assert(client_limit >= used);

	service->total_available_count = client_limit;
	service->master_status.available_count = client_limit - used;
}

unsigned int master_service_get_client_limit(struct master_service *service)
{
	return service->total_available_count;
}

unsigned int master_service_get_process_limit(struct master_service *service)
{
	return service->process_limit;
}

unsigned int master_service_get_process_min_avail(struct master_service *service)
{
	return service->process_min_avail;
}

unsigned int master_service_get_idle_kill_secs(struct master_service *service)
{
	return service->idle_kill_secs;
}

void master_service_set_service_count(struct master_service *service,
				      unsigned int count)
{
	unsigned int used;

	used = service->total_available_count -
		service->master_status.available_count;
	i_assert(count >= used);

	if (service->total_available_count > count) {
		service->total_available_count = count;
		service->master_status.available_count = count - used;
	}
	service->service_count_left = count;
}

unsigned int master_service_get_service_count(struct master_service *service)
{
	return service->service_count_left;
}

unsigned int master_service_get_socket_count(struct master_service *service)
{
	return service->socket_count;
}

const char *master_service_get_socket_name(struct master_service *service,
					   int listen_fd)
{
	unsigned int i;

	i_assert(listen_fd >= MASTER_LISTEN_FD_FIRST);

	i = listen_fd - MASTER_LISTEN_FD_FIRST;
	i_assert(i < service->socket_count);
	return service->listeners[i].name != NULL ?
		service->listeners[i].name : "";
}

void master_service_set_avail_overflow_callback(struct master_service *service,
	master_service_avail_overflow_callback_t *callback)
{
	service->avail_overflow_callback = callback;
}

const char *master_service_get_config_path(struct master_service *service)
{
	return service->config_path;
}

const char *master_service_get_version_string(struct master_service *service)
{
	return service->version_string;
}

const char *master_service_get_name(struct master_service *service)
{
	return service->name;
}

const char *master_service_get_configured_name(struct master_service *service)
{
	return service->configured_name;
}

void master_service_run(struct master_service *service,
			master_service_connection_callback_t *callback)
{
	service->callback = callback;
	io_loop_run(service->ioloop);
	service->callback = NULL;
}

void master_service_stop(struct master_service *service)
{
	io_loop_stop(service->ioloop);
}

void master_service_stop_new_connections(struct master_service *service)
{
	unsigned int current_count;

	if (service->stopping)
		return;

	service->stopping = TRUE;
	master_service_io_listeners_remove(service);
	master_service_io_listeners_close(service);

	/* make sure we stop after servicing current connections */
	current_count = service->total_available_count -
		service->master_status.available_count;
	service->service_count_left = current_count;
	service->total_available_count = current_count;

	if (current_count == 0)
		master_service_stop(service);
	else {
		/* notify master that we're not accepting any more
		   connections */
		service->master_status.available_count = 0;
		master_status_update(service);
	}
	if (service->login != NULL)
		master_login_stop(service->login);
}

bool master_service_is_killed(struct master_service *service)
{
	return service->killed_signal != 0;
}

int master_service_get_kill_signal(struct master_service *service)
{
	return service->killed_signal;
}

void master_service_get_kill_time(struct master_service *service,
				  struct timeval *tv_r)
{
	/* block the signal to avoid races accessing killed_time */
	sigset_t oldmask;
	bool sigterm_blocked = block_sigterm(&oldmask) == 0;

	*tv_r = service->killed_time;

	if (sigterm_blocked) {
		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
			i_error("sigprocmask(SIG_SETMASK) failed: %m");
	}
}

bool master_service_is_master_stopped(struct master_service *service)
{
	return service->io_status_error == NULL &&
		(service->flags & MASTER_SERVICE_FLAG_STANDALONE) == 0;
}

static bool
master_service_anvil_send(struct master_service *service, const char *cmd)
{
	ssize_t ret;

	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0)
		return FALSE;

	ret = write(MASTER_ANVIL_FD, cmd, strlen(cmd));
	if (ret < 0) {
		if (errno == EPIPE) {
			/* anvil process was probably recreated, don't bother
			   logging an error about losing connection to it */
			return FALSE;
		}
		i_error("write(anvil) failed: %m");
		return FALSE;
	} else if (ret == 0) {
		i_error("write(anvil) failed: EOF");
		return FALSE;
	} else {
		i_assert((size_t)ret == strlen(cmd));
		return TRUE;
	}
}

static void
master_service_anvil_session_to_cmd(string_t *cmd,
	const struct master_service_anvil_session *session)
{
	str_printfa(cmd, "%s\t", my_pid);
	str_append_tabescaped(cmd, session->username);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, session->service_name);
	str_append_c(cmd, '\t');
	if (session->ip.family != 0)
		str_append(cmd, net_ip2addr(&session->ip));
}

bool master_service_anvil_connect(struct master_service *service,
	const struct master_service_anvil_session *session,
	bool kick_supported, guid_128_t conn_guid_r)
{
	guid_128_generate(conn_guid_r);

	string_t *cmd = t_str_new(128);
	str_append(cmd, "CONNECT\t");
	str_append(cmd, guid_128_to_string(conn_guid_r));
	str_append_c(cmd, '\t');
	master_service_anvil_session_to_cmd(cmd, session);
	str_append_c(cmd, '\t');
	if (!kick_supported)
		str_append_c(cmd, 'N');
	else if (master_service_get_client_limit(service) > 1)
		str_append_c(cmd, 'A');
	else if (service->have_admin_sockets)
		str_append_c(cmd, 'W');
	else
		str_append_c(cmd, 'S');
	str_append_c(cmd, '\t');
	if (session->dest_ip.family != 0)
		str_append(cmd, net_ip2addr(&session->dest_ip));
	if (session->alt_usernames != NULL) {
		string_t *alt_usernames = t_str_new(64);
		for (unsigned int i = 0; session->alt_usernames[i] != NULL; i++) {
			if (i > 0)
				str_append_c(alt_usernames, '\t');
			str_append_tabescaped(alt_usernames,
					      session->alt_usernames[i]);
		}
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, str_c(alt_usernames));
	}
	str_append_c(cmd, '\n');
	return master_service_anvil_send(service, str_c(cmd));
}

void master_service_anvil_disconnect(struct master_service *service,
	const struct master_service_anvil_session *session,
	const guid_128_t conn_guid)
{
	string_t *cmd = t_str_new(128);
	str_append(cmd, "DISCONNECT\t");
	str_append(cmd, guid_128_to_string(conn_guid));
	str_append_c(cmd, '\t');
	master_service_anvil_session_to_cmd(cmd, session);
	str_append_c(cmd, '\n');
	(void)master_service_anvil_send(service, str_c(cmd));
}

void master_service_client_connection_created(struct master_service *service)
{
	i_assert(service->master_status.available_count > 0);
	service->master_status.available_count--;
	master_status_update(service);
}

static bool master_service_want_listener(struct master_service *service)
{
	if (service->master_status.available_count > 0) {
		/* more concurrent clients can still be added */
		return TRUE;
	}
	if (service->service_count_left == 1) {
		/* after handling this client, the whole process will stop. */
		return FALSE;
	}
	if (service->avail_overflow_callback != NULL) {
		/* overflow callback is set. it's possible that the current
		   existing client may be replaced by a new client, which needs
		   the listener to try to accept new connections. */
		return TRUE;
	}
	/* the listener isn't needed until the current client is disconnected */
	return FALSE;
}

void master_service_client_connection_handled(struct master_service *service,
					      struct master_service_connection *conn)
{
	if (!conn->accepted) {
		if (close(conn->fd) < 0)
			i_error("close(service connection) failed: %m");
		master_service_client_connection_destroyed(service);
	} else if (conn->fifo) {
		/* reading FIFOs stays open forever, don't count them
		   as real clients */
		master_service_client_connection_destroyed(service);
	}
	if (!master_service_want_listener(service)) {
		i_assert(service->listeners != NULL);
		master_service_io_listeners_remove(service);
		if (service->service_count_left == 1 &&
		   service->avail_overflow_callback == NULL) {
			/* we're not going to accept any more connections after
			   this. go ahead and close the connection early. don't
			   do this before calling callback, because it may want
			   to access the listen_fd (e.g. to check socket
			   permissions).

			   Don't do this if overflow callback is set, because
			   otherwise it's never called with service_count=1.
			   Actually this isn't important anymore to do with
			   any service, since nowadays master can request the
			   listeners to be closed via SIGQUIT. Still, closing
			   the fd when possible saves a little bit of memory. */
			master_service_io_listeners_close(service);
		}
	}
}

void master_service_client_connection_callback(struct master_service *service,
					       struct master_service_connection *conn)
{
	service->callback(conn);

	master_service_client_connection_handled(service, conn);
}

void master_service_client_connection_accept(struct master_service_connection *conn)
{
	conn->accepted = TRUE;
}

void master_service_client_connection_destroyed(struct master_service *service)
{
	/* we can listen again */
	master_service_io_listeners_add(service);

	i_assert(service->total_available_count > 0);
	i_assert(service->service_count_left > 0);

	if (service->service_count_left == service->total_available_count) {
		service->total_available_count--;
		service->service_count_left--;
	} else {
		if (service->service_count_left != UINT_MAX)
			service->service_count_left--;

		i_assert(service->master_status.available_count <
			 service->total_available_count);
		service->master_status.available_count++;
	}

	if (service->service_count_left == 0) {
		i_assert(service->master_status.available_count ==
			 service->total_available_count);
		master_service_stop(service);
	} else if ((service->io_status_error == NULL ||
		    service->listeners == NULL) &&
		   service->master_status.available_count ==
		   service->total_available_count) {
		/* we've finished handling all clients, and
		   a) master has closed the connection
		   b) there are no listeners (std-client?) */
		master_service_stop(service);
	} else {
		master_status_update(service);
	}
}

static void master_service_set_login_state(struct master_service *service,
					   enum master_login_state state)
{
	timeout_remove(&service->to_overflow_state);

	switch (state) {
	case MASTER_LOGIN_STATE_NONFULL:
		service->call_avail_overflow = FALSE;
		if (service->master_status.available_count > 0)
			return;

		/* some processes should now be able to handle new connections,
		   although we can't. but there may be race conditions, so
		   make sure that we'll check again soon if the state has
		   changed to "full" without our knowledge. */
		service->to_overflow_state =
			timeout_add(MASTER_SERVICE_STATE_CHECK_MSECS,
				    master_service_refresh_login_state,
				    service);
		return;
	case MASTER_LOGIN_STATE_FULL:
		/* make sure we're listening for more connections */
		service->call_avail_overflow = TRUE;
		master_service_io_listeners_add(service);
		return;
	}
	i_error("Invalid master login state: %d", state);
}

static int master_service_get_login_state(enum master_login_state *state_r)
{
	off_t ret;

	ret = lseek(MASTER_LOGIN_NOTIFY_FD, 0, SEEK_CUR);
	if (ret < 0) {
		i_error("lseek(login notify fd) failed: %m");
		return -1;
	}
	*state_r = ret == MASTER_LOGIN_STATE_FULL ?
		MASTER_LOGIN_STATE_FULL : MASTER_LOGIN_STATE_NONFULL;
	return 0;
}

static void master_service_refresh_login_state(struct master_service *service)
{
	enum master_login_state state;

	if (master_service_get_login_state(&state) == 0)
		master_service_set_login_state(service, state);
}

void master_service_close_config_fd(struct master_service *service)
{
	i_close_fd(&service->config_fd);
}

static void master_service_deinit_real(struct master_service **_service)
{
	struct master_service *service = *_service;

	*_service = NULL;

	if (master_service_is_killed(service) &&
	    (service->killed_signal != SIGINT ||
	     (service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0))
		log_killed_signal(service, &service->killed_signal_info);

	if (!service->init_finished &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME) == 0) {
		if (!t_pop(&service->datastack_frame_id))
			i_panic("Leaked t_pop() call");
	}
	master_admin_clients_deinit();
	master_service_haproxy_abort(service);

	for (unsigned int i = 0; i < service->socket_count; i++)
		io_remove(&service->listeners[i].io);
	master_service_ssl_ctx_deinit(service);

	if (service->stats_client != NULL)
		stats_client_deinit(&service->stats_client);
	master_service_close_config_fd(service);
	timeout_remove(&service->to_overflow_call);
	timeout_remove(&service->to_die);
	timeout_remove(&service->to_overflow_state);
	timeout_remove(&service->to_status);
	io_remove(&service->io_status_error);
	io_remove(&service->io_status_write);
	if (array_is_created(&service->config_overrides))
		array_free(&service->config_overrides);

	if (service->set_parser != NULL) {
		settings_parser_deinit(&service->set_parser);
		pool_unref(&service->set_pool);
	}
	i_free(master_service_category_name);
	master_service_category.name = NULL;
	event_unregister_callback(master_service_event_callback);
	master_service_unset_process_shutdown_filter(service);
}

static void master_service_free(struct master_service *service)
{
	unsigned int i;

	for (i = 0; i < service->socket_count; i++)
		i_free(service->listeners[i].name);
	i_free(service->listeners);
	i_free(service->getopt_str);
	i_free(service->configured_name);
	i_free(service->name);
	i_free(service->config_path);
	i_free(service->current_user);
	i_free(service->last_kick_signal_user);
	i_free(service);
}

void master_service_deinit(struct master_service **_service)
{
	struct master_service *service = *_service;

	master_service_deinit_real(_service);

	lib_signals_deinit();
	/* run atexit callbacks before destroying ioloop */
	lib_atexit_run();
	io_loop_destroy(&service->ioloop);

	master_service_free(service);
	lib_deinit();
}

void master_service_deinit_forked(struct master_service **_service)
{
	struct master_service *service = *_service;

	master_service_deinit_real(_service);
	io_loop_destroy(&service->ioloop);

	master_service_free(service);
}

static void master_service_overflow(struct master_service *service)
{
	enum master_login_state state;
	struct timeval created;

	timeout_remove(&service->to_overflow_call);

	if (master_service_get_login_state(&state) < 0 ||
	    state != MASTER_LOGIN_STATE_FULL) {
		/* service is no longer full (or we couldn't check if it is) */
		return;
	}

	if (!service->avail_overflow_callback(TRUE, &created)) {
		/* can't kill the client anymore after all */
		return;
	}
	if (service->master_status.available_count == 0) {
		/* Client was destroyed, but service_count is now 0.
		   The servive was already stopped, so the process will
		   shutdown and a new process can handle the waiting client
		   connection. */
		i_assert(service->service_count_left == 0);
		i_assert(!io_loop_is_running(service->ioloop));
		return;
	}
	master_service_io_listeners_add(service);

	/* The connection is soon accepted by the listener IO callback.
	   Note that this often results in killing two connections, because
	   after the first process has accepted the new client the service is
	   full again. The second process sees this and kills another client.
	   After this the other processes see that the service is no longer
	   full and kill no more clients. */
}

static unsigned int
master_service_overflow_timeout_msecs(const struct timeval *created)
{
	/* Returns a value between 0..max_wait. The oldest clients return the
	   lowest wait so they get killed before newer clients. For simplicity
	   this code treats all clients older than 10 seconds the same. */
	const unsigned int max_wait = 100;
	const int max_since = 10*1000;
	int created_since = timeval_diff_msecs(&ioloop_timeval, created);
	unsigned int msecs;

	created_since = I_MAX(created_since, 0);
	created_since = I_MIN(created_since, max_since);

	msecs = created_since * max_wait / max_since;
	i_assert(msecs <= max_wait);
	msecs = max_wait - msecs;

	/* Add some extra randomness, so even if all clients have exactly the
	   same creation time they won't all be killed. */
	return msecs + i_rand_limit(10);
}

static bool master_service_full(struct master_service *service)
{
	struct timeval created;

	/* This process can't handle any more connections. */
	if (!service->call_avail_overflow ||
	    service->avail_overflow_callback == NULL)
		return TRUE;

	/* Master has notified us that all processes are full, and
	   we have the ability to kill old connections. */
	if (service->total_available_count > 1) {
		/* This process can still create multiple concurrent
		   clients if we just kill some of the existing ones.
		   Do it immediately. */
		return !service->avail_overflow_callback(TRUE, &created);
	}

	/* This process can't create more than a single client. Most likely
	   running with service_count=1. Check the overflow again after a short
	   delay before killing anything. This way only some of the connections
	   get killed instead of all of them. The delay is based on the
	   connection age with a bit of randomness, so the oldest connections
	   should die first, but even if all the connections have time same
	   timestamp they still don't all die at once. */
	if (!service->avail_overflow_callback(FALSE, &created)) {
		/* can't kill any clients */
		return TRUE;
	}
	i_assert(service->to_overflow_call == NULL);
	service->to_overflow_call =
		timeout_add(master_service_overflow_timeout_msecs(&created),
			    master_service_overflow, service);
	return TRUE;
}

static void
master_service_accept(struct master_service_listener *l, const char *conn_name,
		      bool master_admin_conn)
{
	struct master_service *service = l->service;
	struct master_service_connection conn;

	i_zero(&conn);
	conn.listen_fd = l->fd;
	conn.fd = net_accept(l->fd, &conn.remote_ip, &conn.remote_port);
	if (conn.fd < 0) {
		struct stat st;
		int orig_errno = errno;

		if (conn.fd == -1)
			return;

		if (errno == ENOTSOCK) {
			/* it's not a socket. should be a fifo. */
		} else if (errno == EINVAL &&
			   (fstat(l->fd, &st) == 0 && S_ISFIFO(st.st_mode))) {
			/* BSDI fails accept(fifo) with EINVAL. */
		} else {
			errno = orig_errno;
			i_error("net_accept() failed: %m");
			/* try again later after one of the existing
			   connections has died */
			master_service_io_listeners_remove(service);
			return;
		}
		/* use the "listener" as the connection fd and stop the
		   listener. */
		conn.fd = l->fd;
		conn.listen_fd = l->fd;
		conn.fifo = TRUE;

		io_remove(&l->io);
		l->fd = -1;
	}
	conn.ssl = l->ssl;
	conn.name = conn_name;

	(void)net_getsockname(conn.fd, &conn.local_ip, &conn.local_port);
	conn.real_remote_ip = conn.remote_ip;
	conn.real_remote_port = conn.remote_port;
	conn.real_local_ip = conn.local_ip;
	conn.real_local_port = conn.local_port;

	net_set_nonblock(conn.fd, TRUE);

	if (master_admin_conn) {
		master_admin_client_create(&conn);
		return;
	}
	master_service_client_connection_created(service);
	if (l->haproxy)
		master_service_haproxy_new(service, &conn);
	else
		master_service_client_connection_callback(service, &conn);
}

static void master_service_listen(struct master_service_listener *l)
{
	struct master_service *service = l->service;
	const char *conn_name;
	bool master_admin_conn;

	conn_name = master_service_get_socket_name(service, l->fd);
	master_admin_conn = master_admin_client_can_accept(conn_name);

	if (service->master_status.available_count == 0 && !master_admin_conn) {
		if (master_service_full(service)) {
			/* Stop the listener until a client has disconnected or
			   overflow callback has killed one. */
			master_service_io_listeners_remove(service);
			return;
		}
		/* we can accept another client */
		i_assert(service->master_status.available_count > 0);
	}

	sigset_t oldmask;
	bool sigterm_blocked = FALSE;
	if (master_admin_conn) {
		/* Keep SIGTERM blocked while handling a master-admin
		   connection. This prevents race conditions with the SIGTERM
		   being received while handling the KICK-USER-SIGNAL
		   command. */
		sigterm_blocked = block_sigterm(&oldmask) == 0;
	}
	master_service_accept(l, conn_name, master_admin_conn);
	if (sigterm_blocked) {
		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
			i_error("sigprocmask(SIG_SETMASK) failed: %m");
	}
}

void master_service_io_listeners_add(struct master_service *service)
{
	unsigned int i;

	/* If there's a pending overflow call, remove it now since new
	   clients just became available. */
	timeout_remove(&service->to_overflow_call);

	if (service->stopping)
		return;

	for (i = 0; i < service->socket_count; i++) {
		struct master_service_listener *l = &service->listeners[i];

		if (l->io == NULL && l->fd != -1 && !l->closed) {
			l->io = io_add(MASTER_LISTEN_FD_FIRST + i, IO_READ,
				       master_service_listen, l);
		}
	}
}

void master_service_io_listeners_remove(struct master_service *service)
{
	unsigned int i;

	for (i = 0; i < service->socket_count; i++) {
		if (!master_admin_client_can_accept(service->listeners[i].name))
			io_remove(&service->listeners[i].io);
	}
}

void master_service_ssl_io_listeners_remove(struct master_service *service)
{
	unsigned int i;

	for (i = 0; i < service->socket_count; i++) {
		if (service->listeners[i].io != NULL &&
		    service->listeners[i].ssl)
			io_remove(&service->listeners[i].io);
	}
}

static void master_service_io_listeners_close(struct master_service *service)
{
	unsigned int i;

	/* close via listeners. some fds might be pipes that are
	   currently handled as clients. we don't want to close them. */
	for (i = 0; i < service->socket_count; i++) {
		if (service->listeners[i].fd != -1 &&
		    !master_admin_client_can_accept(service->listeners[i].name)) {
			if (close(service->listeners[i].fd) < 0) {
				i_error("close(listener %d) failed: %m",
					service->listeners[i].fd);
			}
			service->listeners[i].fd = -1;
		}
	}
}

static bool master_status_update_is_important(struct master_service *service)
{
	if (service->master_status.available_count == 0) {
		/* client_limit reached for this process */
		return TRUE;
	}
	if (service->last_sent_status_avail_count == 0) {
		/* This process can now handle more clients. This is important
		   to know for master if all the existing processes have
		   avail_count=0 so it doesn't unnecessarily create more
		   processes. */
		return TRUE;
	}
	/* The previous check should have triggered also for the initial
	   status notification. */
	i_assert(service->initial_status_sent);
	return FALSE;
}

static void
master_status_send(struct master_service *service, bool important_update)
{
	ssize_t ret;

	timeout_remove(&service->to_status);

	ret = write(MASTER_STATUS_FD, &service->master_status,
		    sizeof(service->master_status));
	if (ret == (ssize_t)sizeof(service->master_status)) {
		/* success */
		io_remove(&service->io_status_write);
		service->last_sent_status_time = ioloop_time;
		service->last_sent_status_avail_count =
			service->master_status.available_count;
		service->initial_status_sent = TRUE;
	} else if (ret >= 0) {
		/* shouldn't happen? */
		i_error("write(master_status_fd) returned %d", (int)ret);
		service->master_status.pid = 0;
		io_remove(&service->io_status_write);
	} else if (errno != EAGAIN) {
		/* failure */
		if (errno != EPIPE)
			i_error("write(master_status_fd) failed: %m");
		service->master_status.pid = 0;
		io_remove(&service->io_status_write);
	} else if (important_update) {
		/* reader is busy, but it's important to get this notification
		   through. send it when possible. */
		if (service->io_status_write == NULL) {
			service->io_status_write =
				io_add(MASTER_STATUS_FD, IO_WRITE,
				       master_status_update, service);
		}
	}
	if (service->io_status_waiting &&
	    service->io_status_write == NULL) {
		/* Waiting in an inner ioloop in master_status_update_wait()
		   for the status write to finish (succeed or permanently
		   fail) */
		io_loop_stop(current_ioloop);
	}
}

void master_status_update(struct master_service *service)
{
	bool important_update;

	if ((service->flags & MASTER_SERVICE_FLAG_UPDATE_PROCTITLE) != 0 &&
	    service->set != NULL && service->set->verbose_proctitle) T_BEGIN {
		unsigned int used_count = service->total_available_count -
			service->master_status.available_count;

		process_title_set(t_strdup_printf("[%u connections]",
						  used_count));
	} T_END;

	important_update = master_status_update_is_important(service);
	if (service->master_status.pid == 0 ||
	    service->master_status.available_count ==
	    service->last_sent_status_avail_count) {
		/* a) closed, b) updating to same state */
		timeout_remove(&service->to_status);
		io_remove(&service->io_status_write);
		return;
	}
	if (ioloop_time == service->last_sent_status_time &&
	    !important_update) {
		/* don't spam master */
		if (service->to_status != NULL)
			timeout_reset(service->to_status);
		else {
			service->to_status =
				timeout_add(1000, master_status_update,
					    service);
		}
		if (service->io_status_write != NULL)
			io_remove(&service->io_status_write);
		return;
	}
	master_status_send(service, important_update);
}

bool version_string_verify(const char *line, const char *service_name,
			   unsigned major_version)
{
	unsigned int minor_version;

	return version_string_verify_full(line, service_name,
					  major_version, &minor_version);
}

bool version_string_verify_full(const char *line, const char *service_name,
				unsigned major_version,
				unsigned int *minor_version_r)
{
	size_t service_name_len = strlen(service_name);
	bool ret;

	if (!str_begins(line, "VERSION\t", &line))
		return FALSE;

	if (strncmp(line, service_name, service_name_len) != 0 ||
	    line[service_name_len] != '\t')
		return FALSE;
	line += service_name_len + 1;

	T_BEGIN {
		const char *p = strchr(line, '\t');

		if (p == NULL)
			ret = FALSE;
		else {
			ret = str_uint_equals(t_strdup_until(line, p),
					      major_version);
			if (str_to_uint(p+1, minor_version_r) < 0)
				ret = FALSE;
		}
	} T_END;
	return ret;
}

void master_service_set_process_shutdown_filter(struct master_service *service,
						struct event_filter *filter)
{
	master_service_unset_process_shutdown_filter(service);
	service->process_shutdown_filter = filter;
	event_filter_ref(service->process_shutdown_filter);
}

void master_service_unset_process_shutdown_filter(struct master_service *service)
{
	event_filter_unref(&service->process_shutdown_filter);
}

void master_service_set_current_user(struct master_service *service,
				     const char *user)
{
	/* block the signal to avoid races accessing current_user */
	sigset_t oldmask;
	bool sigterm_blocked = block_sigterm(&oldmask) == 0;

	char *old_user = service->current_user;
	service->current_user = i_strdup(user);
	i_free(old_user);

	if (sigterm_blocked) {
		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
			i_error("sigprocmask(SIG_SETMASK) failed: %m");
	}
}

void master_service_set_last_kick_signal_user(struct master_service *service,
					      const char *user)
{
	/* block the signal to avoid races accessing last_kick_signal_user */
	sigset_t oldmask;
	bool sigterm_blocked = block_sigterm(&oldmask) == 0;

	i_free(service->last_kick_signal_user);
	service->last_kick_signal_user = i_strdup(user);
	service->last_kick_signal_user_accessed = 0;

	if (sigterm_blocked) {
		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
			i_error("sigprocmask(SIG_SETMASK) failed: %m");
	}
}
