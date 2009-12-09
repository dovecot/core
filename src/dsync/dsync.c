/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "dsync-brain.h"
#include "dsync-worker.h"
#include "dsync-proxy-server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static struct dsync_brain *brain;
static struct dsync_proxy_server *server;

static void run_cmd(const char *cmd, int *fd_in_r, int *fd_out_r)
{
	char **args;
	int fd_in[2], fd_out[2];

	if (pipe(fd_in) < 0 || pipe(fd_out) < 0)
		i_fatal("pipe() failed: %m");

	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
		break;
	case 0:
		/* child, which will execute the proxy server. stdin/stdout
		   goes to pipes which we'll pass to proxy client. */
		if (dup2(fd_in[0], STDIN_FILENO) < 0 ||
		    dup2(fd_out[1], STDOUT_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		(void)close(fd_in[0]);
		(void)close(fd_in[1]);
		(void)close(fd_out[0]);
		(void)close(fd_out[1]);

		args = p_strsplit(pool_datastack_create(), cmd, " ");
		(void)execvp(args[0], args);
		i_fatal("execve(%s) failed: %m", args[0]);
		break;
	default:
		/* parent */
		(void)close(fd_in[0]);
		(void)close(fd_out[1]);
		*fd_in_r = fd_out[0];
		*fd_out_r = fd_in[1];
		break;
	}
}

static void ATTR_NORETURN
usage(void)
{
	fprintf(stderr,
"usage: dsync [-a <alt hierarchy sep>] [-b <mailbox>] [-r] [-u <user>] [-v]\n"
"  mirror  <command to execute remote dsync>\n"
"  convert <source mail_location>\n"
);
	exit(1);
}

static void
dsync_connected(const struct master_service_connection *conn ATTR_UNUSED)
{
	i_fatal("Running as service not supported currently");
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags ssflags =
		MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR;
	enum dsync_brain_flags brain_flags = 0;
	struct mail_storage_service_ctx *storage_service;
	struct mail_storage_service_user *service_user;
	struct mail_storage_service_input input;
	struct mail_user *mail_user, *mail_user2 = NULL;
	struct dsync_worker *worker1, *worker2;
	const char *error, *username, *mailbox = NULL, *mirror_cmd = NULL;
	const char *convert_location = NULL;
	bool dsync_server = FALSE, readonly = FALSE, unexpected_changes = FALSE;
	char alt_char = '_';
	int c, ret, fd_in = STDIN_FILENO, fd_out = STDOUT_FILENO;

	master_service = master_service_init("dsync",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "A:b:fru:v");

	username = getenv("USER");
	while ((c = master_getopt(master_service)) > 0) {
		if (c == '-')
			break;
		switch (c) {
		case 'A':
			alt_char = optarg[0];
			break;
		case 'b':
			mailbox = optarg;
			break;
		case 'r':
			readonly = TRUE;
			break;
		case 'f':
			brain_flags |= DSYNC_BRAIN_FLAG_FULL_SYNC;
			break;
		case 'u':
			username = optarg;
			ssflags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			break;
		case 'v':
			brain_flags |= DSYNC_BRAIN_FLAG_VERBOSE;
			break;
		default:
			usage();
		}
	}
	if (optind == argc)
		usage();

	if (strcmp(argv[optind], "mirror") == 0 && optind+1 != argc) {
		mirror_cmd = argv[optind+1];
		optind += 2;
	} else if (strcmp(argv[optind], "server") == 0) {
		dsync_server = TRUE;
		optind++;
	} else if (strcmp(argv[optind], "convert") == 0 &&
		   optind+1 != argc) {
		convert_location = argv[optind+1];
		optind += 2;
	}
	if (optind != argc)
		usage();
	master_service_init_finish(master_service);

	memset(&input, 0, sizeof(input));
	input.username = username;

	storage_service = mail_storage_service_init(master_service, NULL,
						    ssflags);
	if (mail_storage_service_lookup(storage_service, &input,
					&service_user, &error) <= 0)
		i_fatal("User lookup failed: %s", error);
	if (mail_storage_service_next(storage_service, service_user,
				      &mail_user, &error) < 0)
		i_fatal("User init failed: %s", error);

	if (mirror_cmd != NULL) {
		/* user initialization may exec doveconf, so do our forking
		   after that */
		run_cmd(t_strconcat(mirror_cmd, " server", NULL),
			&fd_in, &fd_out);
	}

	/* create the first local worker */
	worker1 = dsync_worker_init_local(mail_user, alt_char);
	if (convert_location != NULL) {
		/* update mail_location and create another user for the
		   second location. */
		struct setting_parser_context *set_parser;
		const char *set_line =
			t_strconcat("mail_location=", convert_location, NULL);

		set_parser = mail_storage_service_user_get_settings_parser(service_user);
		if (settings_parse_line(set_parser, set_line) < 0)
			i_unreached();
		if (mail_storage_service_next(storage_service, service_user,
					      &mail_user2, &error) < 0)
			i_fatal("User init failed: %s", error);

		worker2 = dsync_worker_init_local(mail_user2, alt_char);

		i_set_failure_prefix(t_strdup_printf("dsync(%s): ", username));
		brain = dsync_brain_init(worker1, worker2,
					 mailbox, brain_flags);
		server = NULL;
		dsync_brain_sync_all(brain);
	} else if (dsync_server) {
		i_set_failure_prefix(t_strdup_printf("dsync-remote(%s): ",
						     username));
		if (readonly)
			dsync_worker_set_readonly(worker1);
		server = dsync_proxy_server_init(fd_in, fd_out, worker1);
		worker2 = NULL;

		master_service_run(master_service, dsync_connected);
	} else {
		i_assert(mirror_cmd != NULL);
		i_set_failure_prefix(t_strdup_printf("dsync-local(%s): ",
						     username));

		if (readonly)
			dsync_worker_set_readonly(worker1);
		worker2 = dsync_worker_init_proxy_client(fd_in, fd_out);
		brain = dsync_brain_init(worker1, worker2,
					 mailbox, brain_flags);
		server = NULL;
		dsync_brain_sync(brain);

		master_service_run(master_service, dsync_connected);
	}

	if (brain == NULL)
		ret = 0;
	else {
		if (dsync_brain_has_unexpected_changes(brain))
			unexpected_changes = TRUE;
		ret = dsync_brain_deinit(&brain);
	}
	if (server != NULL)
		dsync_proxy_server_deinit(&server);

	dsync_worker_deinit(&worker1);
	if (worker2 != NULL)
		dsync_worker_deinit(&worker2);

	mail_user_unref(&mail_user);
	if (mail_user2 != NULL)
		mail_user_unref(&mail_user2);
	mail_storage_service_user_free(&service_user);

	if (unexpected_changes &&
	    (brain_flags & DSYNC_BRAIN_FLAG_VERBOSE) != 0) {
		i_info("Mailbox changes caused a desync. "
		       "You might want to run dsync again.");
	}

	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return ret < 0 ? 1 : (unexpected_changes ? 2 : 0);
}
