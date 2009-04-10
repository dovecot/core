/* Copyright (C) 2005-2009 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "env-util.h"
#include "home-expand.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "syslog-util.h"
#include "master-service-private.h"
#include "master-service-settings.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define DEFAULT_CONFIG_FILE_PATH SYSCONFDIR"/dovecot.conf"

/* getenv(MASTER_CONFIG_FILE_ENV) provides path to configuration file/socket */
#define MASTER_CONFIG_FILE_ENV "CONFIG_FILE"

/* getenv(MASTER_DOVECOT_VERSION_ENV) provides master's version number */
#define MASTER_DOVECOT_VERSION_ENV "DOVECOT_VERSION"

const char *master_service_getopt_string(void)
{
	return "c:Lk";
}

static void sig_die(const siginfo_t *si, void *context)
{
	struct master_service *service = context;

	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (si->si_signo != SIGINT) {
		i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
			  si->si_signo, dec2str(si->si_pid),
			  dec2str(si->si_uid),
			  lib_signal_code_to_str(si->si_signo, si->si_code));
	}
	io_loop_stop(service->ioloop);
}

static void master_service_verify_version(struct master_service *service)
{
	if (service->version_string != NULL &&
	    strcmp(service->version_string, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, %s is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)",
			service->name, service->version_string);
	}
}

struct master_service *
master_service_init(const char *name, enum master_service_flags flags,
		    int argc, char *argv[])
{
	struct master_service *service;

	i_assert(name != NULL);

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	/* Set a logging prefix temporarily. This will be ignored once the log
	   is properly initialized */
	i_set_failure_prefix(t_strdup_printf("%s(init): ", name));

	if (getenv("LOG_TO_MASTER") == NULL)
		flags |= MASTER_SERVICE_FLAG_STANDALONE;

	service = i_new(struct master_service, 1);
	service->argc = argc;
	service->argv = argv;
	service->name = i_strdup(name);
	service->flags = flags;
	service->ioloop = io_loop_create();
	service->config_path = getenv(MASTER_CONFIG_FILE_ENV);
	if (service->config_path == NULL)
		service->config_path = DEFAULT_CONFIG_FILE_PATH;

	if ((flags & MASTER_SERVICE_FLAG_STANDALONE) == 0)
		service->version_string = getenv(MASTER_DOVECOT_VERSION_ENV);
	else
		service->version_string = PACKAGE_VERSION;

	/* set up some kind of logging until we know exactly how and where
	   we want to log */
	if (getenv("LOG_TO_MASTER") != NULL)
		i_set_failure_internal();
	if (getenv("USER") != NULL) {
		i_set_failure_prefix(t_strdup_printf("%s(%s): ",
						     name, getenv("USER")));
	} else {
		i_set_failure_prefix(t_strdup_printf("%s: ", name));
	}

	/* set default signal handlers */
	lib_signals_init();
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
        lib_signals_set_handler(SIGINT, TRUE, sig_die, service);
	lib_signals_set_handler(SIGTERM, TRUE, sig_die, service);

	master_service_verify_version(service);
	return service;
}

void master_service_init_log(struct master_service *service, const char *prefix)
{
	const char *path;

	if (getenv("LOG_TO_MASTER") != NULL && !service->log_directly) {
		/* logging via master process */
		i_set_failure_internal();
		i_set_failure_prefix(prefix);
		return;
	}

	if (*service->set->log_path == '\0') {
		/* log to syslog */
		int facility;

		if (!syslog_facility_find(service->set->syslog_facility,
					  &facility))
			facility = LOG_MAIL;
		i_set_failure_syslog("dovecot", LOG_NDELAY, facility);
		i_set_failure_prefix(prefix);
	} else {
		/* log to file or stderr */
		path = home_expand(service->set->log_path);
		i_set_failure_file(path, prefix);
	}

	path = home_expand(service->set->info_log_path);
	if (*path != '\0')
		i_set_info_file(path);
	i_set_failure_timestamp_format(service->set->log_timestamp);
}

bool master_service_parse_option(struct master_service *service,
				 int opt, const char *arg)
{
	switch (opt) {
	case 'c':
		service->config_path = arg;
		break;
	case 'k':
		service->keep_environment = TRUE;
		break;
	case 'L':
		service->log_directly = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

void master_service_env_clean(bool preserve_home)
{
	const char *user, *tz, *home;

	user = getenv("USER");
	if (user != NULL)
		user = t_strconcat("USER=", user, NULL);
	tz = getenv("TZ");
	if (tz != NULL)
		tz = t_strconcat("TZ=", tz, NULL);
	home = preserve_home ? getenv("HOME") : NULL;
	if (home != NULL)
		home = t_strconcat("HOME=", home, NULL);

	/* Note that if the original environment was set with env_put(), the
	   environment strings will be invalid after env_clean(). That's why
	   we t_strconcat() them above. */
	env_clean();

	if (user != NULL) env_put(user);
	if (tz != NULL) env_put(tz);
	if (home != NULL) env_put(home);
}

const char *master_service_get_config_path(struct master_service *service)
{
	return service->config_path;
}

const char *master_service_get_version_string(struct master_service *service)
{
	return service->version_string;
}

void master_service_run(struct master_service *service)
{
	io_loop_run(service->ioloop);
}

void master_service_stop(struct master_service *service)
{
        io_loop_stop(service->ioloop);
}

void master_service_deinit(struct master_service **_service)
{
	struct master_service *service = *_service;

	*_service = NULL;
	lib_signals_deinit();
	io_loop_destroy(&service->ioloop);

	i_free(service->name);
	i_free(service);

	lib_deinit();
}
