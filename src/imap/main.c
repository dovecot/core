/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "base64.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-storage-service.h"
#include "commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

static struct io *log_io = NULL;

struct master_service *service;
void (*hook_client_created)(struct client **client) = NULL;

static void log_error_callback(void *context ATTR_UNUSED)
{
	/* the log fd is closed, don't die when trying to log later */
	i_set_failure_ignore_errors(TRUE);

	master_service_stop(service);
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

static void main_init(const struct imap_settings *set, struct mail_user *user,
		      bool dump_capability)
{
	struct client *client;
	struct ostream *output;
	const char *str, *tag;

	if (set->shutdown_clients && !dump_capability) {
		/* If master dies, the log fd gets closed and we'll quit */
		log_io = io_add(STDERR_FILENO, IO_ERROR,
				log_error_callback, NULL);
	}

	clients_init();
	commands_init();

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
	commands_deinit();
}

int main(int argc, char *argv[], char *envp[])
{
	const struct setting_parser_info *set_roots[] = {
		&imap_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags = 0;
	struct mail_user *mail_user;
	const struct imap_settings *set;
	const char *user;
	bool dump_capability;
	int c;

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

	if (IS_STANDALONE())
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE;
	else
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;

	dump_capability = getenv("DUMP_CAPABILITY") != NULL;
	if (dump_capability) {
		storage_service_flags |=
			MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS;
	}

	service = master_service_init("imap", service_flags, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(service, c, optarg))
			i_fatal("Unknown argument: %c", c);
	}

	user = getenv("USER");
	if (user == NULL) {
		if (IS_STANDALONE())
			user = getlogin();
		if (user == NULL)
			i_fatal("USER environment missing");
	}

	mail_user = mail_storage_service_init_user(service, user, set_roots,
						   storage_service_flags);
	set = mail_storage_service_get_settings(service);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	/* fake that we're running, so we know if client was destroyed
	   while initializing */
	io_loop_set_running(current_ioloop);

	main_init(set, mail_user, dump_capability);
	if (io_loop_is_running(current_ioloop))
		master_service_run(service);

	main_deinit();
	mail_storage_service_deinit_user();
	master_service_deinit(&service);
	return 0;
}
