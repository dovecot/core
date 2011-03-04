/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "execv-const.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "dsync-brain.h"
#include "dsync-worker.h"
#include "dsync-proxy-server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

static const char *ssh_cmd = "ssh";
static struct dsync_brain *brain;
static struct dsync_proxy_server *server;

static void run_cmd(const char *const *args, int *fd_in_r, int *fd_out_r)
{
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

		execvp_const(args[0], args);
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

static void
mirror_get_remote_cmd_line(char **argv, const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	unsigned int i;
	const char *p;

	t_array_init(&cmd_args, 16);
	for (i = 0; argv[i] != NULL; i++) {
		p = argv[i];
		array_append(&cmd_args, &p, 1);
	}

	p = "server"; array_append(&cmd_args, &p, 1);
	(void)array_append_space(&cmd_args);
	*cmd_args_r = array_idx(&cmd_args, 0);
}

static bool mirror_get_remote_cmd(char **argv, const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	const char *p, *user, *host;

	if (argv[1] != NULL) {
		/* more than one parameter, so it contains a full command
		   (e.g. ssh host dsync) */
		mirror_get_remote_cmd_line(argv, cmd_args_r);
		return TRUE;
	}

	/* if it begins with /[a-z0-9]+:/, it's a mail location
	   (e.g. mdbox:~/mail) */
	for (p = argv[0]; *p != '\0'; p++) {
		if (!i_isalnum(*p)) {
			if (*p == ':')
				return FALSE;
			break;
		}
	}

	if (strchr(argv[0], ' ') != NULL || strchr(argv[0], '/') != NULL) {
		/* a) the whole command is in one string. this is mainly for
		      backwards compatibility.
		   b) script/path */
		argv = p_strsplit(pool_datastack_create(), argv[0], " ");
		mirror_get_remote_cmd_line(argv, cmd_args_r);
		return TRUE;
	}

	/* [user@]host */
	host = strchr(argv[0], '@');
	if (host != NULL)
		user = t_strdup_until(argv[0], host++);
	else {
		user = "";
		host = argv[0];
	}

	/* we'll assume virtual users, so in user@host it really means not to
	   give ssh a username, but to give dsync -u user parameter. */
	t_array_init(&cmd_args, 8);
	array_append(&cmd_args, &ssh_cmd, 1);
	array_append(&cmd_args, &host, 1);
	p = "dsync"; array_append(&cmd_args, &p, 1);
	if (*user != '\0') {
		p = "-u"; array_append(&cmd_args, &p, 1);
		array_append(&cmd_args, &user, 1);
	}
	p = "server"; array_append(&cmd_args, &p, 1);
	(void)array_append_space(&cmd_args);
	*cmd_args_r = array_idx(&cmd_args, 0);
	return TRUE;
}

static void ATTR_NORETURN
usage(void)
{
	fprintf(stderr,
"usage: dsync [-C <alt char>] [-m <mailbox>] [-u <user>] [-frRv]\n"
"  mirror <local mail_location> | [<user>@]<host> | <remote dsync command>\n"
);
	exit(1);
}

static void
dsync_connected(struct master_service_connection *conn ATTR_UNUSED)
{
	i_fatal("Running as service not supported currently");
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags ssflags =
		MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	enum dsync_brain_flags brain_flags = 0;
	struct mail_storage_service_ctx *storage_service;
	struct mail_storage_service_user *service_user;
	struct mail_storage_service_input input;
	struct mail_user *mail_user, *mail_user2 = NULL;
	struct dsync_worker *worker1, *worker2, *workertmp;
	const char *error, *username, *cmd_name, *mailbox = NULL;
	const char *local_location = NULL, *const *remote_cmd_args = NULL;
	const char *path1, *path2;
	bool dsync_server = FALSE, unexpected_changes = FALSE;
	bool dsync_debug = FALSE, reverse_workers = FALSE;
	char alt_char = '_';
	int c, ret, fd_in = STDIN_FILENO, fd_out = STDOUT_FILENO;

	master_service = master_service_init("dsync",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "+C:Dfm:Ru:v");

	username = getenv("USER");
	while ((c = master_getopt(master_service)) > 0) {
		if (c == '-')
			break;
		switch (c) {
		case 'C':
			alt_char = optarg[0];
			break;
		case 'D':
			dsync_debug = TRUE;
			brain_flags |= DSYNC_BRAIN_FLAG_VERBOSE;
			ssflags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;
			break;
		case 'm':
			mailbox = optarg;
			break;
		case 'R':
			reverse_workers = TRUE;
			break;
		case 'f':
			brain_flags |= DSYNC_BRAIN_FLAG_FULL_SYNC;
			break;
		case 'u':
			username = optarg;
			ssflags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			ssflags &= ~MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR;
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
	if (username == NULL)
		i_fatal("USER environment not set and -u parameter not given");
	cmd_name = argv[optind++];

	if (strcmp(cmd_name, "mirror") == 0 ||
	    strcmp(cmd_name, "convert") == 0 ||
	    strcmp(cmd_name, "backup") == 0) {
		if (optind == argc)
			usage();

		if (strcmp(cmd_name, "backup") == 0)
			brain_flags |= DSYNC_BRAIN_FLAG_BACKUP;
		if (!mirror_get_remote_cmd(argv+optind, &remote_cmd_args)) {
			if (optind+1 != argc)
				usage();
			local_location = argv[optind];
		}
		optind++;
	} else if (strcmp(cmd_name, "server") == 0) {
		dsync_server = TRUE;
	} else {
		usage();
	}
	master_service_init_finish(master_service);

	if (!dsync_debug) {
		/* disable debugging unless -D is given */
		i_set_debug_file("/dev/null");
	}

	memset(&input, 0, sizeof(input));
	input.module = "mail";
	input.service = "dsync";
	input.username = username;

	storage_service = mail_storage_service_init(master_service, NULL,
						    ssflags);
	if (mail_storage_service_lookup(storage_service, &input,
					&service_user, &error) <= 0)
		i_fatal("User lookup failed: %s", error);

	if (remote_cmd_args != NULL) {
		/* _service_lookup() may exec doveconf, so do our forking
		   after that. but do it before _service_next() in case it
		   drops process privileges */
		run_cmd(remote_cmd_args, &fd_in, &fd_out);
	}

	if (mail_storage_service_next(storage_service, service_user,
				      &mail_user) < 0)
		i_fatal("User init failed");

	/* create the first local worker */
	worker1 = dsync_worker_init_local(mail_user, alt_char);
	if (local_location != NULL) {
		/* update mail_location and create another user for the
		   second location. */
		struct setting_parser_context *set_parser;
		const char *set_line =
			t_strconcat("mail_location=", local_location, NULL);

		set_parser = mail_storage_service_user_get_settings_parser(service_user);
		if (settings_parse_line(set_parser, set_line) < 0)
			i_unreached();
		if (mail_storage_service_next(storage_service, service_user,
					      &mail_user2) < 0)
			i_fatal("User init failed");

		if (mail_namespaces_get_root_sep(mail_user->namespaces) !=
		    mail_namespaces_get_root_sep(mail_user2->namespaces)) {
			i_fatal("Mail locations must use the same "
				"virtual mailbox hierarchy separator "
				"(specify separator for the default namespace)");
		}
		path1 = mailbox_list_get_path(mail_user->namespaces->list, NULL,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		path2 = mailbox_list_get_path(mail_user2->namespaces->list, NULL,
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(path1, path2) == 0) {
			i_fatal("Both source and destination mail_location "
				"points to same directory: %s", path1);
		}

		worker2 = dsync_worker_init_local(mail_user2, alt_char);
		if (reverse_workers) {
			workertmp = worker1;
			worker1 = worker2;
			worker2 = workertmp;
		}

		i_set_failure_prefix(t_strdup_printf("dsync(%s): ", username));
		brain = dsync_brain_init(worker1, worker2, mailbox,
					 brain_flags | DSYNC_BRAIN_FLAG_LOCAL);
		server = NULL;
		dsync_brain_sync_all(brain);
	} else if (dsync_server) {
		i_set_failure_prefix(t_strdup_printf("dsync-remote(%s): ",
						     username));
		server = dsync_proxy_server_init(fd_in, fd_out, worker1);
		worker2 = NULL;

		master_service_run(master_service, dsync_connected);
	} else {
		i_assert(remote_cmd_args != NULL);
		i_set_failure_prefix(t_strdup_printf("dsync-local(%s): ",
						     username));

		worker2 = dsync_worker_init_proxy_client(fd_in, fd_out);
		if (reverse_workers) {
			workertmp = worker1;
			worker1 = worker2;
			worker2 = workertmp;
		}

		brain = dsync_brain_init(worker1, worker2,
					 mailbox, brain_flags);
		server = NULL;
		dsync_brain_sync(brain);

		if (!dsync_brain_has_failed(brain))
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

	if (unexpected_changes) {
		i_warning("Mailbox changes caused a desync. "
			  "You may want to run dsync again.");
	}

	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return ret < 0 ? 1 : (unexpected_changes ? 2 : 0);
}
