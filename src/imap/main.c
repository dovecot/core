/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "str.h"
#include "base64.h"
#include "istream.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "module-dir.h"
#include "dict.h"
#include "mail-storage.h"
#include "commands.h"
#include "mail-namespace.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#define IS_STANDALONE() \
        (getenv("IMAPLOGINTAG") == NULL)

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

static struct client_workaround_list client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "outlook-idle", 0 }, /* only for backwards compatibility */
	{ "netscape-eoh", WORKAROUND_NETSCAPE_EOH },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ NULL, 0 }
};

struct ioloop *ioloop;

static struct io *log_io = NULL;
static struct module *modules = NULL;
static char log_prefix[128]; /* syslog() needs this to be permanent */

void (*hook_client_created)(struct client **client) = NULL;

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	/* warn about being killed because of some signal, except SIGINT (^C)
	   which is too common at least while testing :) */
	if (si->si_signo != SIGINT) {
		i_warning("Killed with signal %d (by pid=%s uid=%s code=%s)",
			  si->si_signo, dec2str(si->si_pid),
			  dec2str(si->si_uid),
			  lib_signal_code_to_str(si->si_signo, si->si_code));
	}
	io_loop_stop(ioloop);
}

static void log_error_callback(void *context ATTR_UNUSED)
{
	/* the log fd is closed, don't die when trying to log later */
	i_set_failure_ignore_errors(TRUE);

	io_loop_stop(ioloop);
}

static enum client_workarounds
parse_workarounds(const struct imap_settings *set)
{
        enum client_workarounds client_workarounds = 0;
        struct client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imap_client_workarounds, " ,");
	for (; *str != NULL; str++) {
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

	return client_workarounds;
}

static void open_logfile(void)
{
	const char *user;

	if (getenv("LOG_TO_MASTER") != NULL) {
		i_set_failure_internal();
		return;
	}

	if (getenv("LOG_PREFIX") != NULL)
		i_strocpy(log_prefix, getenv("LOG_PREFIX"), sizeof(log_prefix));
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

static void main_preinit(const struct imap_settings **set_r,
			 const struct mail_user_settings **user_set_r)
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

        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	/* read settings after registering storages so they can have their
	   own setting definitions too */
	imap_settings_read(set_r, user_set_r);

	/* Load the plugins before chrooting. Their init() is called later. */
	modules = *(*set_r)->mail_plugins == '\0' ? NULL :
		module_dir_load((*set_r)->mail_plugin_dir,
				(*set_r)->mail_plugins, TRUE, version);

	restrict_access_by_env(getenv("HOME"), !IS_STANDALONE());
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(const struct imap_settings *set,
		      const struct mail_user_settings *user_set)
{
	struct client *client;
	struct ostream *output;
	struct mail_user *user;
	const char *username, *home, *str, *tag, *error;
	bool dump_capability;

	lib_signals_init();
        lib_signals_set_handler(SIGINT, TRUE, sig_die, NULL);
        lib_signals_set_handler(SIGTERM, TRUE, sig_die, NULL);
        lib_signals_ignore(SIGPIPE, TRUE);
        lib_signals_ignore(SIGALRM, FALSE);
	
	dump_capability = getenv("DUMP_CAPABILITY") != NULL;

	username = getenv("USER");
	if (username == NULL) {
		if (IS_STANDALONE())
			username = getlogin();
		if (username == NULL)
			i_fatal("USER environment missing");
	}

	home = getenv("HOME");
	if (set->mail_debug) {
		home = getenv("HOME");
		i_info("Effective uid=%s, gid=%s, home=%s",
		       dec2str(geteuid()), dec2str(getegid()),
		       home != NULL ? home : "(none)");
	}

	if (set->shutdown_clients && !dump_capability) {
		/* If master dies, the log fd gets closed and we'll quit */
		log_io = io_add(STDERR_FILENO, IO_ERROR,
				log_error_callback, NULL);
	}

	dict_drivers_register_builtin();
	mail_users_init(set->auth_socket_path, set->mail_debug);
	clients_init();
	commands_init();

	module_dir_init(modules);

	user = mail_user_alloc(username, user_set);
	mail_user_set_home(user, home);
	if (mail_user_init(user, &error) < 0)
		i_fatal("Mail user initialization failed: %s", error);
	if (mail_namespaces_init(user, &error) < 0)
		i_fatal("Namespace initialization failed: %s", error);
	client = client_create(0, 1, user, set);
        client->workarounds = parse_workarounds(set);

	if (dump_capability) {
		printf("%s\n", str_c(client->capability_string));
		exit(0);
	}

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);

	/* IMAPLOGINTAG environment is compatible with mailfront */
	tag = getenv("IMAPLOGINTAG");
	if (tag == NULL) {
		client_send_line(client, t_strconcat(
			"* PREAUTH [CAPABILITY ",
			str_c(client->capability_string), "] "
			"Logged in as ", user->username, NULL));
	} else {
		client_send_line(client, t_strconcat(
			tag, " OK [CAPABILITY ",
			str_c(client->capability_string), "] Logged in", NULL));
	}
	str = getenv("CLIENT_INPUT");
	if (str != NULL) T_BEGIN {
		buffer_t *buf = t_base64_decode_str(str);
		if (buf->used > 0) {
			if (!i_stream_add_data(client->input, buf->data,
					       buf->used))
				i_panic("Couldn't add client input to stream");
			(void)client_handle_input(client);
		}
	} T_END;
        o_stream_uncork(output);
	o_stream_unref(&output);
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_deinit();

	module_dir_unload(&modules);
	commands_deinit();
	mail_storage_deinit();
	mail_users_deinit();
	dict_drivers_unregister_builtin();

	lib_signals_deinit();
	closelog();
}

int main(int argc ATTR_UNUSED, char *argv[], char *envp[])
{
	const struct imap_settings *set;
	const struct mail_user_settings *user_set;

#ifdef DEBUG
	if (!IS_STANDALONE() && getenv("GDB") == NULL)
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
	main_preinit(&set, &user_set);

        process_title_init(argv, envp);
	ioloop = io_loop_create();

	/* fake that we're running, so we know if client was destroyed
	   while initializing */
	io_loop_set_running(ioloop);
	main_init(set, user_set);
	if (io_loop_is_running(ioloop))
		io_loop_run(ioloop);
	main_deinit();

	io_loop_destroy(&ioloop);
	lib_deinit();

	return 0;
}
