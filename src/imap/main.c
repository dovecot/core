/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "str.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "randgen.h"
#include "module-dir.h"
#include "dict-client.h"
#include "mail-storage.h"
#include "commands.h"
#include "mail-namespace.h"
#include "imap-thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL && getenv("IMAPLOGINTAG") == NULL)

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

struct client_workaround_list client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "outlook-idle", WORKAROUND_OUTLOOK_IDLE },
	{ "netscape-eoh", WORKAROUND_NETSCAPE_EOH },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ NULL, 0 }
};

struct ioloop *ioloop;
unsigned int max_keyword_length;
unsigned int imap_max_line_length;
enum client_workarounds client_workarounds = 0;
static struct io *log_io = NULL;

static struct module *modules = NULL;
static char log_prefix[128]; /* syslog() needs this to be permanent */
static pool_t namespace_pool;

void (*hook_client_created)(struct client **client) = NULL;

string_t *capability_string;

static void sig_die(int signo, void *context __attr_unused__)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (signo != SIGINT)
		i_warning("Killed with signal %d", signo);
	io_loop_stop(ioloop);
}

static void log_error_callback(void *context __attr_unused__)
{
	io_loop_stop(ioloop);
}

static void parse_workarounds(void)
{
        struct client_workaround_list *list;
	const char *env, *const *str;

	env = getenv("IMAP_CLIENT_WORKAROUNDS");
	if (env == NULL)
		return;

	for (str = t_strsplit_spaces(env, " ,"); *str != NULL; str++) {
		list = client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL)
			i_fatal("Unknown client workaround: %s", *str);
	}
}

static void open_logfile(void)
{
	const char *user;

	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

	if (getenv("LOG_PREFIX") != NULL)
		strocpy(log_prefix, getenv("LOG_PREFIX"), sizeof(log_prefix));
	else {
		user = getenv("USER");
		if (user == NULL) {
			if (IS_STANDALONE())
				user = getlogin();
			if (user == NULL)
				user = "??";
		}
		if (strlen(user) >= sizeof(log_prefix)-6) {
			/* quite a long user name, cut it */
			user = t_strndup(user, sizeof(log_prefix)-6-2);
			user = t_strconcat(user, "..", NULL);
		}
		i_snprintf(log_prefix, sizeof(log_prefix), "imap(%s): ", user);
	}
	if (getenv("USE_SYSLOG") != NULL) {
		const char *env = getenv("SYSLOG_FACILITY");
		i_set_failure_syslog(log_prefix, LOG_NDELAY,
				     env == NULL ? LOG_MAIL : atoi(env));
	} else {
		/* log to file or stderr */
		i_set_failure_file(getenv("LOGFILE"), log_prefix);
	}

	if (getenv("INFOLOGFILE") != NULL)
		i_set_info_file(getenv("INFOLOGFILE"));

	i_set_failure_timestamp_format(getenv("LOGSTAMP"));
}

static void drop_privileges(void)
{
	const char *version;

	version = getenv("DOVECOT_VERSION");
	if (version != NULL && strcmp(version, PACKAGE_VERSION) != 0) {
		i_fatal("Dovecot version mismatch: "
			"Master is v%s, imap is v"PACKAGE_VERSION" "
			"(if you don't care, set version_ignore=yes)", version);
	}

	/* Log file or syslog opening probably requires roots */
	open_logfile();

	/* Most likely needed. Have to open /dev/urandom before possible
	   chrooting. */
	random_init();

	/* Load the plugins before chrooting. Their init() is called later. */
	if (getenv("MAIL_PLUGINS") != NULL) {
		const char *plugin_dir = getenv("MAIL_PLUGIN_DIR");

		if (plugin_dir == NULL)
			plugin_dir = MODULEDIR"/imap";
		modules = module_dir_load(plugin_dir, getenv("MAIL_PLUGINS"),
					  TRUE, version);
	}

	restrict_access_by_env(!IS_STANDALONE());
}

static void main_init(void)
{
	struct client *client;
	struct mail_namespace *ns;
	const char *user, *str;

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);

	user = getenv("USER");
	if (user == NULL) {
		if (IS_STANDALONE())
			user = getlogin();
		if (user == NULL)
			i_fatal("USER environment missing");
	}

	if (getenv("DEBUG") != NULL) {
		const char *home;

		home = getenv("HOME");
		i_info("Effective uid=%s, gid=%s, home=%s",
		       dec2str(geteuid()), dec2str(getegid()),
		       home != NULL ? home : "(none)");
	}

	if (getenv("STDERR_CLOSE_SHUTDOWN") != NULL) {
		/* If master dies, the log fd gets closed and we'll quit */
		log_io = io_add(STDERR_FILENO, IO_ERROR,
				log_error_callback, NULL);
	}

	capability_string = str_new(default_pool, sizeof(CAPABILITY_STRING)+32);
	str_append(capability_string, CAPABILITY_STRING);

	dict_driver_register(&dict_driver_client);
        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();
	clients_init();
	commands_init();
	imap_thread_init();

	module_dir_init(modules);

	if (getenv("DUMP_CAPABILITY") != NULL) {
		printf("%s\n", str_c(capability_string));
		exit(0);
	}

	str = getenv("IMAP_CAPABILITY");
	if (str != NULL && *str != '\0') {
		/* Overrides all capabilities */
		str_truncate(capability_string, 0);
		str_append(capability_string, str);
	}

	str = getenv("IMAP_MAX_LINE_LENGTH");
	imap_max_line_length = str != NULL ?
		(unsigned int)strtoul(str, NULL, 10) :
		DEFAULT_IMAP_MAX_LINE_LENGTH;

	str = getenv("MAIL_MAX_KEYWORD_LENGTH");
	max_keyword_length = str != NULL ?
		(unsigned int)strtoul(str, NULL, 10) :
		DEFAULT_MAX_KEYWORD_LENGTH;

        parse_workarounds();

	namespace_pool = pool_alloconly_create("namespaces", 1024);
	if (mail_namespaces_init(namespace_pool, user, &ns) < 0)
		exit(FATAL_DEFAULT);
	client = client_create(0, 1, ns);

        o_stream_cork(client->output);
	if (IS_STANDALONE()) {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY ",
			str_c(capability_string), "] "
			"Logged in as ", user, NULL));
	} else if (getenv("IMAPLOGINTAG") != NULL) {
		/* Support for mailfront */
		client_send_line(client, t_strconcat(getenv("IMAPLOGINTAG"),
						     " OK Logged in.", NULL));
	}
        o_stream_uncork(client->output);
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_deinit();

	module_dir_unload(&modules);
	imap_thread_deinit();
	commands_deinit();
        mail_storage_deinit();
	dict_driver_unregister(&dict_driver_client);
	random_deinit();
	pool_unref(namespace_pool);

	str_free(&capability_string);

	lib_signals_deinit();
	closelog();
}

int main(int argc __attr_unused__, char *argv[], char *envp[])
{
#ifdef DEBUG
	if (getenv("LOGGED_IN") != NULL && getenv("GDB") == NULL)
		fd_debug_verify_leaks(3, 1024);
#endif
	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("* BAD [ALERT] imap binary must not be started from "
		       "inetd, use imap-login instead.\n");
		return 1;
	}

	/* NOTE: we start rooted, so keep the code minimal until
	   restrict_access_by_env() is called */
	lib_init();
	drop_privileges();

        process_title_init(argv, envp);
	ioloop = io_loop_create();

	main_init();
        io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

	return 0;
}
