/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "buffer.h"
#include "base64.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "master-service.h"
#include "var-expand.h"
#include "mail-storage-service.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IS_STANDALONE() \
        (getenv("LOGGED_IN") == NULL)

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

static struct client_workaround_list client_workaround_list[] = {
	{ "outlook-no-nuls", WORKAROUND_OUTLOOK_NO_NULS },
	{ "oe-ns-eoh", WORKAROUND_OE_NS_EOH },
	{ NULL, 0 }
};

struct master_service *service;
void (*hook_client_created)(struct client **client) = NULL;

static struct io *log_io = NULL;

static void log_error_callback(void *context ATTR_UNUSED)
{
	/* the log fd is closed, don't die when trying to log later */
	i_set_failure_ignore_errors(TRUE);

	master_service_stop(service);
}

static enum client_workarounds
parse_workarounds(const struct pop3_settings *set)
{
        enum client_workarounds client_workarounds = 0;
	struct client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->pop3_client_workarounds, " ,");
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

static enum uidl_keys parse_uidl_keymask(const char *format)
{
	enum uidl_keys mask = 0;

	for (; *format != '\0'; format++) {
		if (format[0] == '%' && format[1] != '\0') {
			switch (var_get_key(++format)) {
			case 'v':
				mask |= UIDL_UIDVALIDITY;
				break;
			case 'u':
				mask |= UIDL_UID;
				break;
			case 'm':
				mask |= UIDL_MD5;
				break;
			case 'f':
				mask |= UIDL_FILE_NAME;
				break;
			}
		}
	}
	return mask;
}

static bool main_init(const struct pop3_settings *set, struct mail_user *user)
{
	struct client *client;
	const char *str;
	bool ret = TRUE;

	if (set->shutdown_clients) {
		/* If master dies, the log fd gets closed and we'll quit */
		log_io = io_add(STDERR_FILENO, IO_ERROR,
				log_error_callback, NULL);
	}

	clients_init();

	client = client_create(0, 1, user, set);
	if (client == NULL)
		return FALSE;
	client->workarounds = parse_workarounds(set);
	client->uidl_keymask = parse_uidl_keymask(set->pop3_uidl_format);
	if (client->uidl_keymask == 0) {
		i_fatal("pop3_uidl_format setting doesn't contain any "
			"%% variables.");
	}

	if (!IS_STANDALONE())
		client_send_line(client, "+OK Logged in.");

	str = getenv("CLIENT_INPUT");
	if (str != NULL) T_BEGIN {
		buffer_t *buf = t_base64_decode_str(str);
		if (buf->used > 0) {
			if (!i_stream_add_data(client->input, buf->data,
					       buf->used))
				i_panic("Couldn't add client input to stream");
			ret = client_handle_input(client);
		}
	} T_END;
	return ret;
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_deinit();
}

int main(int argc, char *argv[], char *envp[])
{
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;
	struct mail_user *mail_user;
	const struct pop3_settings *set;
	const char *user;
	int c;

#ifdef DEBUG
	if (!IS_STANDALONE() && getenv("GDB") == NULL)
		fd_debug_verify_leaks(3, 1024);
#endif
	if (IS_STANDALONE() && getuid() == 0 &&
	    net_getpeername(1, NULL, NULL) == 0) {
		printf("-ERR pop3 binary must not be started from "
		       "inetd, use pop3-login instead.\n");
		return 1;
	}

	if (IS_STANDALONE())
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE;
	else
		service_flags |= MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT;

	service = master_service_init("pop3", service_flags, argc, argv);
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

	mail_user = mail_storage_service_init_user(service, user,
						   &pop3_setting_parser_info,
						   storage_service_flags);
	set = mail_storage_service_get_settings(service);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	/* fake that we're running, so we know if client was destroyed
	   while initializing */
	io_loop_set_running(current_ioloop);

	if (main_init(set, mail_user))
		master_service_run(service);

	main_deinit();
	mail_storage_service_deinit_user();
	master_service_deinit(&service);
	return 0;
}
