/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "mail-storage.h"

#include <stdlib.h>
#include <syslog.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL)

struct ioloop *ioloop;
static char log_prefix[128]; /* syslog() needs this to be permanent */

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void open_logfile(void)
{
	const char *user;

	user = getenv("USER");
	if (user == NULL) user = "??";
	if (strlen(user) >= sizeof(log_prefix)-6) {
		/* quite a long user name, cut it */
		user = t_strndup(user, sizeof(log_prefix)-6-2);
		user = t_strconcat(user, "..", NULL);
	}
	i_snprintf(log_prefix, sizeof(log_prefix), "pop3(%s)", user);

	if (getenv("USE_SYSLOG") != NULL)
		i_set_failure_syslog(log_prefix, LOG_NDELAY, LOG_MAIL);
	else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), log_prefix);
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static void drop_privileges(void)
{
	/* Log file or syslog opening probably requires roots */
	open_logfile();

	restrict_access_by_env(!IS_STANDALONE());
}

static void main_init(void)
{
	struct client *client;
	struct mail_storage *storage;
	struct mailbox *mailbox;
	const char *mail;

	lib_init_signals(sig_quit);

	if (getenv("USER") == NULL)
		i_fatal("USER environment missing");

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

	mailbox = storage->open_mailbox(storage, "INBOX", FALSE, FALSE);
	if (mailbox == NULL)
		i_fatal("No INBOX for user");

	client = client_create(0, 1, mailbox);
}

static void main_deinit(void)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (lib_signal_kill != 0 && lib_signal_kill != 2)
		i_warning("Killed with signal %d", lib_signal_kill);

	clients_deinit();
        mail_storage_deinit();

	closelog();
}

int main(int argc __attr_unused__, char *argv[], char *envp[])
{
#ifdef DEBUG
	if (getenv("LOGGED_IN") != NULL)
		fd_debug_verify_leaks(3, 1024);
#endif
	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

        process_title_init(argv, envp);
	ioloop = io_loop_create(system_pool);

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(ioloop);
	lib_deinit();

	return 0;
}
