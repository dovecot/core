/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "fd-close-on-exec.h"
#include "process-title.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "client.h"
#include "main.h"

#include <stdlib.h>
#include <unistd.h>

#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv("MASTER_SERVICE") == NULL)

struct lmtp_listener {
	int fd;
	struct io *io;
};

struct master_service *service;
struct mail_storage_service_multi_ctx *multi_service;

static struct io *log_io = NULL;
static ARRAY_DEFINE(listeners, struct lmtp_listener *);

static void log_error_callback(void *context ATTR_UNUSED)
{
	/* the log fd is closed, don't die when trying to log later */
	i_set_failure_ignore_errors(TRUE);

	master_service_stop(service);
}

static void listen_connected(struct lmtp_listener *l)
{
	struct client *client;
	struct ip_addr remote_ip;
	unsigned int remote_port;
	int fd;

	fd = net_accept(l->fd, &remote_ip, &remote_port);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept() failed: %m");
		return;
	}
	client = client_create(fd, fd);
	client->remote_ip = remote_ip;
	client->remote_port = remote_port;

	(void)net_getsockname(fd, &client->local_ip, &client->local_port);
}

static void listen_start(void)
{
	struct lmtp_listener *const *l;
	unsigned int i, count;

	l = array_get(&listeners, &count);
	for (i = 0; i < count; i++) {
		i_assert(l[i]->io == NULL);
		l[i]->io = io_add(l[i]->fd, IO_READ, listen_connected, l[i]);
	}
}

static void listen_stop(void)
{
	struct lmtp_listener *const *l;
	unsigned int i, count;

	l = array_get(&listeners, &count);
	for (i = 0; i < count; i++) {
		i_assert(l[i]->io != NULL);
		io_remove(&l[i]->io);
	}
}

static void listen_free(void)
{
	struct lmtp_listener **l;
	unsigned int i, count;

	l = array_get_modifiable(&listeners, &count);
	for (i = 0; i < count; i++) {
		if (l[i]->io != NULL)
			io_remove(&l[i]->io);
		i_free(l[i]);
	}
	array_free(&listeners);
}

void listener_client_destroyed(void)
{
	if (array_count(&listeners) == 0)
		master_service_stop(service);
}

static void main_init(void)
{
	struct lmtp_listener *l;
	const char *value;
	unsigned int i, count;

	/* If master dies, the log fd gets closed and we'll quit */
	log_io = io_add(STDERR_FILENO, IO_ERROR, log_error_callback, NULL);

	value = getenv("LISTEN_FDS");
	count = value == NULL ? 0 : atoi(value);
	i_array_init(&listeners, count + 1);
	for (i = 0; i < count; i++) {
		l = i_new(struct lmtp_listener, 1);
		l->fd = LMTP_MASTER_FIRST_LISTEN_FD + i;
		array_append(&listeners, &l, 1);
	}

	if (count == 0)
		(void)client_create(STDIN_FILENO, STDOUT_FILENO);
	else
		listen_start();
}

static void main_deinit(void)
{
	if (log_io != NULL)
		io_remove(&log_io);
	clients_destroy();
	listen_free();
}

int main(int argc, char *argv[], char *envp[])
{
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	int c;

#ifdef DEBUG
	if (!IS_STANDALONE() && getenv("GDB") == NULL) {
		const char *env;

		env = getenv("LISTEN_FDS");
		fd_debug_verify_leaks(LMTP_MASTER_FIRST_LISTEN_FD +
				      (env == NULL ? 0 : atoi(env)), 1024);
	}
#endif

	if (IS_STANDALONE())
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE;

	service = master_service_init("lmtp", service_flags, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(service, c, optarg))
			i_fatal("Unknown argument: %c", c);
	}

	multi_service = mail_storage_service_multi_init(service, set_roots,
							storage_service_flags);
	restrict_access_allow_coredumps(TRUE);

        process_title_init(argv, envp);

	main_init();
	master_service_run(service);

	main_deinit();
	mail_storage_service_multi_deinit(&multi_service);
	master_service_deinit(&service);
	return 0;
}
