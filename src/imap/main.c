/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "rawlog.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"

#include <stdlib.h>
#include <syslog.h>

IOLoop ioloop;
static char log_prefix[64];

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void main_init(int use_syslog)
{
	Client *client;
	MailStorage *storage;
	const char *logfile, *mail, *tag;
	int hin, hout;

	hin = 0; hout = 1;

	lib_init_signals(sig_quit);

	i_snprintf(log_prefix, sizeof(log_prefix), "imap(%s)", getenv("USER"));

	logfile = getenv("IMAP_LOGFILE");
	if (logfile != NULL) {
		/* log failures into specified log file */
		i_set_failure_file(logfile, log_prefix);
		i_set_failure_timestamp_format(getenv("IMAP_LOGSTAMP"));
	} else if (use_syslog) {
		/* prefix with imapd(user) */
		openlog(log_prefix, 0, LOG_MAIL);

		i_set_panic_handler(i_syslog_panic_handler);
		i_set_fatal_handler(i_syslog_fatal_handler);
		i_set_error_handler(i_syslog_error_handler);
		i_set_warning_handler(i_syslog_warning_handler);
	}

	/* do the chrooting etc. */
	restrict_access_by_env();

	rawlog_open(&hin, &hout);

	mail_storage_register_all();
	clients_init();

	mail = getenv("MAIL");
	if (mail == NULL) {
		/* support also maildir-specific environment */
		mail = getenv("MAILDIR");
		if (mail != NULL)
			mail = t_strconcat("maildir:", mail, NULL);
	}

	storage = mail_storage_create_with_data(mail, getenv("USER"));
	if (storage == NULL) {
		/* failed */
		if (mail != NULL && *mail != '\0')
			i_fatal("Failed to create storage with data: %s", mail);
		else {
			const char *home;

			home = getenv("HOME");
			if (home == NULL) home = "not set";

			i_fatal("MAIL environment missing and "
				"autodetection failed (home %s)", home);
		}
	}

	client = client_create(hin, hout, storage);

	tag = getenv("LOGIN_TAG");
	if (tag == NULL || *tag == '\0') {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY "CAPABILITY_STRING"] "
			"Logged in as ", getenv("USER"), NULL));
	} else {
		client_send_line(client,
				 t_strconcat(tag, " OK Logged in.", NULL));
	}
}

static void main_deinit(void)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (lib_signal_kill != 0 && lib_signal_kill != 2)
		i_warning("Killed with signal %d", lib_signal_kill);

	clients_deinit();

	closelog();
}

int main(int argc, char *argv[], char *envp[])
{
#ifdef DEBUG
	if (getenv("LOGIN_TAG") != NULL)
		fd_debug_verify_leaks(3, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
        process_title_init(argv, envp);
	ioloop = io_loop_create(system_pool);

	main_init(argc >= 2 && strcmp(argv[1], "-s") == 0);
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

	return 0;
}
