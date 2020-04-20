/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "ioloop.h"
#include "path-util.h"
#include "array.h"
#include "strescape.h"
#include "env-util.h"
#include "home-expand.h"
#include "process-title.h"
#include "restrict-access.h"
#include "settings-parser.h"
#include "syslog-util.h"
#include "stats-client.h"
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
static void master_service_refresh_login_state(struct master_service *service);
static void
master_status_send(struct master_service *service, bool important_update);

const char *master_service_getopt_string(void)
{
	return "c:i:ko:OL";
}

static void sig_die(const siginfo_t *si, void *context)
{
	struct master_service *service = context;

	/* SIGINT comes either from master process or from keyboard. we don't
	   want to log it in either case.*/
	if (si->si_signo != SIGINT) {
		i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
			  si->si_signo, dec2str(si->si_pid),
			  dec2str(si->si_uid),
			  lib_signal_code_to_str(si->si_signo, si->si_code));
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

	service->killed = TRUE;
	io_loop_stop(service->ioloop);
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
sig_state_changed(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct master_service *service = context;

	master_service_refresh_login_state(service);
}

static bool
master_service_event_callback(struct event *event,
			      enum event_callback_type type,
			      struct failure_context *ctx ATTR_UNUSED,
			      const char *fmt ATTR_UNUSED,
			      va_list args ATTR_UNUSED)
{
	if (type == EVENT_CALLBACK_TYPE_CREATE && event->parent == NULL) {
		/* Add service:<name> category for all events. It's enough
		   to do it only for root events, because all other events
		   inherit the category from them. */
		event_add_category(event, &master_service_category);
	}
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
	service->want_ssl_settings = have_ssl_sockets ||
		(service->flags & (MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
				   MASTER_SERVICE_FLAG_HAVE_STARTTLS)) != 0;
}

struct master_service *
master_service_init(const char *name, enum master_service_flags flags,
		    int *argc, char **argv[], const char *getopt_str)
{
	struct master_service *service;
	data_stack_frame_t datastack_frame_id = 0;
	unsigned int count;
	const char *value;

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
	/* Set a logging prefix temporarily. This will be ignored once the log
	   is properly initialized */
	i_set_failure_prefix("%s(init): ", name);

	/* make sure all the data stack allocations during init will be freed
	   before we get to ioloop. the corresponding t_pop() is in
	   master_service_init_finish(). */
	if ((flags & MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME) == 0)
		datastack_frame_id = t_push(NULL);

	/* ignore these signals as early as possible */
	lib_signals_init();
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);

	if (getenv(MASTER_UID_ENV) == NULL)
		flags |= MASTER_SERVICE_FLAG_STANDALONE;

	process_title_init(*argc, argv);

	service = i_new(struct master_service, 1);
	service->argc = *argc;
	service->argv = *argv;
	service->name = i_strdup(name);
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
	/* load SSL module if necessary */
	if (service->want_ssl_settings) {
		const char *error;
		if (ssl_module_load(&error) < 0)
			i_fatal("Cannot load SSL module: %s", error);
		service->ssl_module_loaded = TRUE;
	}
#endif

	/* set up some kind of logging until we know exactly how and where
	   we want to log */
	if (getenv("LOG_SERVICE") != NULL)
		i_set_failure_internal();
	if (getenv("USER") != NULL)
		i_set_failure_prefix("%s(%s): ", name, getenv("USER"));
	else
		i_set_failure_prefix("%s: ", name);

	master_service_category_name =
		i_strdup_printf("service:%s", service->name);
	master_service_category.name = master_service_category_name;
	event_register_callback(master_service_event_callback);

	/* Initialize debug logging */
	value = getenv(DOVECOT_LOG_DEBUG_ENV);
	if (value != NULL) {
		struct event_filter *filter = event_filter_create();
		const char *error;
		if (master_service_log_filter_parse(filter, value, &error) < 0) {
			i_error("Invalid "DOVECOT_LOG_DEBUG_ENV" - ignoring: %s",
				error);
		}
		event_set_global_debug_log_filter(filter);
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

		/* seve the process limit */
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

void master_service_init_log(struct master_service *service,
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

void master_service_init_finish(struct master_service *service)
{
	enum libsig_flags sigint_flags = LIBSIG_FLAG_DELAYED;
	struct stat st;

	i_assert(!service->init_finished);
	service->init_finished = TRUE;

	/* set default signal handlers */
	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) == 0)
		sigint_flags |= LIBSIG_FLAG_RESTART;
        lib_signals_set_handler(SIGINT, sigint_flags, sig_die, service);
	lib_signals_set_handler(SIGTERM, LIBSIG_FLAG_DELAYED, sig_die, service);
	if ((service->flags & MASTER_SERVICE_FLAG_TRACK_LOGIN_STATE) != 0) {
		lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
					sig_state_changed, service);
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
	if (service->want_ssl_settings &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_SSL_INIT) == 0)
		master_service_ssl_ctx_init(service);

	if ((service->flags & MASTER_SERVICE_FLAG_STD_CLIENT) != 0) {
		/* we already have a connection to be served */
		service->master_status.available_count--;
	}
	master_status_update(service);

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
	/* add new environments */
	envs = t_strsplit_spaces(import_environment, " ");
	for (; *envs != NULL; envs++) {
		value = strchr(*envs, '=');
		if (value == NULL)
			key = *envs;
		else {
			key = t_strdup_until(*envs, value);
			env_put(*envs);
		}
		array_push_back(&keys, &key);
	}
	array_append_zero(&keys);

	value = t_strarray_join(array_front(&keys), " ");
	env_put(t_strconcat(DOVECOT_PRESERVE_ENVS_ENV"=", value, NULL));
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
						void (*callback)(void))
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
	return service->killed;
}

bool master_service_is_master_stopped(struct master_service *service)
{
	return service->io_status_error == NULL &&
		(service->flags & MASTER_SERVICE_FLAG_STANDALONE) == 0;
}

void master_service_anvil_send(struct master_service *service, const char *cmd)
{
	ssize_t ret;

	if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0)
		return;

	ret = write(MASTER_ANVIL_FD, cmd, strlen(cmd));
	if (ret < 0) {
		if (errno == EPIPE) {
			/* anvil process was probably recreated, don't bother
			   logging an error about losing connection to it */
			return;
		}
		i_error("write(anvil) failed: %m");
	} else if (ret == 0)
		i_error("write(anvil) failed: EOF");
	else {
		i_assert((size_t)ret == strlen(cmd));
	}
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
		if (service->service_count_left == 1) {
			/* we're not going to accept any more connections after
			   this. go ahead and close the connection early. don't
			   do this before calling callback, because it may want
			   to access the listen_fd (e.g. to check socket
			   permissions). */
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

static void master_service_refresh_login_state(struct master_service *service)
{
	int ret;

	ret = lseek(MASTER_LOGIN_NOTIFY_FD, 0, SEEK_CUR);
	if (ret < 0)
		i_error("lseek(login notify fd) failed: %m");
	else
		master_service_set_login_state(service, ret);
}

void master_service_close_config_fd(struct master_service *service)
{
	i_close_fd(&service->config_fd);
}

void master_service_deinit(struct master_service **_service)
{
	struct master_service *service = *_service;
	unsigned int i;

	*_service = NULL;

	if (!service->init_finished &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME) == 0) {
		if (!t_pop(&service->datastack_frame_id))
			i_panic("Leaked t_pop() call");
	}
	master_service_haproxy_abort(service);

	master_service_io_listeners_remove(service);
	master_service_ssl_ctx_deinit(service);

	if (service->stats_client != NULL)
		stats_client_deinit(&service->stats_client);
	master_service_close_config_fd(service);
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
	lib_signals_deinit();
	/* run atexit callbacks before destroying ioloop */
	lib_atexit_run();
	io_loop_destroy(&service->ioloop);

	for (i = 0; i < service->socket_count; i++)
		i_free(service->listeners[i].name);
	i_free(service->listeners);
	i_free(service->getopt_str);
	i_free(service->name);
	i_free(service->config_path);
	i_free(service);

	lib_deinit();
}

static void master_service_listen(struct master_service_listener *l)
{
	struct master_service *service = l->service;
	struct master_service_connection conn;

	if (service->master_status.available_count == 0) {
		/* we are full. stop listening for now, unless overflow
		   callback destroys one of the existing connections */
		if (service->call_avail_overflow &&
		    service->avail_overflow_callback != NULL)
			service->avail_overflow_callback();

		if (service->master_status.available_count == 0) {
			master_service_io_listeners_remove(service);
			return;
		}
	}

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
	conn.name = master_service_get_socket_name(service, conn.listen_fd);

	(void)net_getsockname(conn.fd, &conn.local_ip, &conn.local_port);
	conn.real_remote_ip = conn.remote_ip;
	conn.real_remote_port = conn.remote_port;
	conn.real_local_ip = conn.local_ip;
	conn.real_local_port = conn.local_port;

	net_set_nonblock(conn.fd, TRUE);

	master_service_client_connection_created(service);
	if (l->haproxy)
		master_service_haproxy_new(service, &conn);
	else
		master_service_client_connection_callback(service, &conn);
}

void master_service_io_listeners_add(struct master_service *service)
{
	unsigned int i;

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
		if (service->listeners[i].fd != -1) {
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
	if (service->master_status.available_count == 0)
		return TRUE;
	if (!service->initial_status_sent)
		return TRUE;
	return FALSE;
}

static void
master_status_send(struct master_service *service, bool important_update)
{
	ssize_t ret;

	timeout_remove(&service->to_status);

	ret = write(MASTER_STATUS_FD, &service->master_status,
		    sizeof(service->master_status));
	if (ret == sizeof(service->master_status)) {
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
	} else if (errno != EAGAIN) {
		/* failure */
		if (errno != EPIPE)
			i_error("write(master_status_fd) failed: %m");
		service->master_status.pid = 0;
	} else if (important_update) {
		/* reader is busy, but it's important to get this notification
		   through. send it when possible. */
		if (service->io_status_write == NULL) {
			service->io_status_write =
				io_add(MASTER_STATUS_FD, IO_WRITE,
				       master_status_update, service);
		}
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

	if (!str_begins(line, "VERSION\t"))
		return FALSE;
	line += 8;

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

bool master_service_is_ssl_module_loaded(struct master_service *service)
{
	/* if this is TRUE, then ssl module is loaded by init */
	return service->ssl_module_loaded;
}
