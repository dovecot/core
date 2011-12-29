/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "execv-const.h"
#include "settings-parser.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "dsync-brain.h"
#include "dsync-worker.h"
#include "dsync-proxy-server.h"
#include "doveadm-dsync.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

struct dsync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum dsync_brain_flags brain_flags;
	const char *mailbox;

	const char *const *remote_cmd_args;
	const char *local_location;

	int fd_in, fd_out;

	unsigned int reverse_workers:1;
};

static const char *ssh_cmd = "ssh";

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
mirror_get_remote_cmd_line(const char *const *argv,
			   const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	unsigned int i;
	const char *p;

	t_array_init(&cmd_args, 16);
	for (i = 0; argv[i] != NULL; i++) {
		p = argv[i];
		array_append(&cmd_args, &p, 1);
	}

	p = strchr(argv[0], '/');
	if (p == NULL) p = argv[0];
	if (strstr(p, "dsync") == NULL) {
		/* we're executing doveadm (not dsync) */
		p = "dsync"; array_append(&cmd_args, &p, 1);
	}
	p = "server"; array_append(&cmd_args, &p, 1);
	(void)array_append_space(&cmd_args);
	*cmd_args_r = array_idx(&cmd_args, 0);
}

static bool mirror_get_remote_cmd(const char *const *argv, const char *user,
				  const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	const char *p, *host;

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
		mirror_get_remote_cmd_line(t_strsplit(argv[0], " "),
					   cmd_args_r);
		return TRUE;
	}

	/* [user@]host */
	host = strchr(argv[0], '@');
	if (host != NULL)
		user = t_strdup_until(argv[0], host++);
	else
		host = argv[0];

	/* we'll assume virtual users, so in user@host it really means not to
	   give ssh a username, but to give dsync -u user parameter. */
	t_array_init(&cmd_args, 8);
	array_append(&cmd_args, &ssh_cmd, 1);
	array_append(&cmd_args, &host, 1);
	p = "doveadm"; array_append(&cmd_args, &p, 1);
	p = "dsync"; array_append(&cmd_args, &p, 1);
	p = "server"; array_append(&cmd_args, &p, 1);
	if (*user != '\0') {
		p = "-u"; array_append(&cmd_args, &p, 1);
		array_append(&cmd_args, &user, 1);
	}
	(void)array_append_space(&cmd_args);
	*cmd_args_r = array_idx(&cmd_args, 0);
	return TRUE;
}

static struct dsync_worker *
cmd_dsync_run_local(struct dsync_cmd_context *ctx, struct mail_user *user)
{
	struct mail_user *user2;
	struct dsync_worker *worker2;
	struct setting_parser_context *set_parser;
	const char *set_line, *path1, *path2;

	i_assert(ctx->local_location != NULL);

	ctx->brain_flags |= DSYNC_BRAIN_FLAG_LOCAL;
	i_set_failure_prefix(t_strdup_printf("dsync(%s): ", user->username));

	/* update mail_location and create another user for the
	   second location. */
	set_parser = mail_storage_service_user_get_settings_parser(ctx->ctx.cur_service_user);
	set_line = t_strconcat("mail_location=", ctx->local_location, NULL);
	if (settings_parse_line(set_parser, set_line) < 0)
		i_unreached();
	if (mail_storage_service_next(ctx->ctx.storage_service,
				      ctx->ctx.cur_service_user, &user2) < 0)
		i_fatal("User init failed");
	user2->admin = TRUE;

	if (mail_namespaces_get_root_sep(user->namespaces) !=
	    mail_namespaces_get_root_sep(user2->namespaces)) {
		i_fatal("Mail locations must use the same "
			"virtual mailbox hierarchy separator "
			"(specify separator for the default namespace)");
	}
	path1 = mailbox_list_get_path(user->namespaces->list, NULL,
				      MAILBOX_LIST_PATH_TYPE_MAILBOX);
	path2 = mailbox_list_get_path(user2->namespaces->list, NULL,
				      MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (path1 != NULL && path2 != NULL &&
	    strcmp(path1, path2) == 0) {
		i_fatal("Both source and destination mail_location "
			"points to same directory: %s", path1);
	}

	worker2 = dsync_worker_init_local(user2, *ctx->ctx.set->dsync_alt_char);
	mail_user_unref(&user2);
	return worker2;
}

static struct dsync_worker *
cmd_dsync_run_remote(struct dsync_cmd_context *ctx, struct mail_user *user)
{
	i_set_failure_prefix(t_strdup_printf("dsync-local(%s): ",
					     user->username));
	return dsync_worker_init_proxy_client(ctx->fd_in, ctx->fd_out);
}

static void
cmd_dsync_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	struct dsync_worker *worker1, *worker2, *workertmp;
	struct dsync_brain *brain;

	user->admin = TRUE;

	/* create workers */
	worker1 = dsync_worker_init_local(user, *_ctx->set->dsync_alt_char);
	if (ctx->remote_cmd_args == NULL)
		worker2 = cmd_dsync_run_local(ctx, user);
	else
		worker2 = cmd_dsync_run_remote(ctx, user);
	if (ctx->reverse_workers) {
		workertmp = worker1;
		worker1 = worker2;
		worker2 = workertmp;
	}

	/* create and run the brain */
	brain = dsync_brain_init(worker1, worker2, ctx->mailbox,
				 ctx->brain_flags);
	if (ctx->remote_cmd_args == NULL)
		dsync_brain_sync_all(brain);
	else {
		dsync_brain_sync(brain);
		if (!dsync_brain_has_failed(brain))
			io_loop_run(current_ioloop);
	}
	/* deinit */
	if (dsync_brain_has_unexpected_changes(brain)) {
		i_warning("Mailbox changes caused a desync. "
			  "You may want to run dsync again.");
		_ctx->exit_code = 2;
	}
	if (dsync_brain_deinit(&brain) < 0)
		_ctx->exit_code = 1;

	dsync_worker_deinit(&worker1);
	dsync_worker_deinit(&worker2);
}

static void cmd_dsync_init(struct doveadm_mail_cmd_context *_ctx,
			   const char *const args[])
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	const char *username = "";

	if (args[0] == NULL)
		doveadm_mail_help_name("dsync");

	lib_signals_ignore(SIGHUP, TRUE);

	if (doveadm_debug || doveadm_verbose)
		ctx->brain_flags |= DSYNC_BRAIN_FLAG_VERBOSE;

	/* if we're executing remotely, give -u parameter if we also
	   did a userdb lookup. this works only when we're handling a
	   single user */
	if ((_ctx->service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0 &&
	    _ctx->cur_username != NULL)
		username = _ctx->cur_username;
	if (!mirror_get_remote_cmd(args, username, &ctx->remote_cmd_args)) {
		/* it's a mail_location */
		if (args[1] != NULL)
			doveadm_mail_help_name("dsync");
		ctx->local_location = args[0];
	}

	if (ctx->remote_cmd_args != NULL) {
		/* do this before mail_storage_service_next() in case it
		   drops process privileges */
		run_cmd(ctx->remote_cmd_args, &ctx->fd_in, &ctx->fd_out);
	} else {
		ctx->fd_in = STDIN_FILENO;
		ctx->fd_out = STDOUT_FILENO;
	}
}

static void cmd_dsync_preinit(struct doveadm_mail_cmd_context *ctx)
{
	if ((ctx->service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) == 0)
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR;
}

static bool
cmd_mailbox_dsync_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;

	switch (c) {
	case 'f':
		ctx->brain_flags |= DSYNC_BRAIN_FLAG_FULL_SYNC;
		break;
	case 'm':
		ctx->mailbox = optarg;
		break;
	case 'R':
		ctx->reverse_workers = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_dsync_alloc(void)
{
	struct dsync_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct dsync_cmd_context);
	ctx->ctx.getopt_args = "fRm:";
	ctx->ctx.v.parse_arg = cmd_mailbox_dsync_parse_arg;
	ctx->ctx.v.preinit = cmd_dsync_preinit;
	ctx->ctx.v.init = cmd_dsync_init;
	ctx->ctx.v.run = cmd_dsync_run;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_dsync_backup_alloc(void)
{
	struct doveadm_mail_cmd_context *_ctx;
	struct dsync_cmd_context *ctx;

	_ctx = cmd_dsync_alloc();
	ctx = (struct dsync_cmd_context *)_ctx;
	ctx->brain_flags |= DSYNC_BRAIN_FLAG_BACKUP;
	return _ctx;
}

static void
cmd_dsync_server_run(struct doveadm_mail_cmd_context *ctx,
		     struct mail_user *user)
{
	struct dsync_proxy_server *server;
	struct dsync_worker *worker;

	user->admin = TRUE;

	i_set_failure_prefix(t_strdup_printf("dsync-remote(%s): ",
					     user->username));
	worker = dsync_worker_init_local(user, *ctx->set->dsync_alt_char);
	server = dsync_proxy_server_init(STDIN_FILENO, STDOUT_FILENO, worker);

	io_loop_run(current_ioloop);

	dsync_proxy_server_deinit(&server);
	dsync_worker_deinit(&worker);
}

static struct doveadm_mail_cmd_context *cmd_dsync_server_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_dsync_server_run;
	return ctx;
}

struct doveadm_mail_cmd cmd_dsync_mirror = {
	cmd_dsync_alloc, "dsync mirror", "[-fR] [-m <mailbox>] <dest>"
};
struct doveadm_mail_cmd cmd_dsync_backup = {
	cmd_dsync_backup_alloc, "dsync backup",
	"[-fR] [-m <mailbox>] <dest>"
};
struct doveadm_mail_cmd cmd_dsync_server = {
	cmd_dsync_server_alloc, "dsync server", NULL
};

void doveadm_dsync_main(int *_argc, char **_argv[])
{
	int argc = *_argc;
	const char *getopt_str;
	char **argv = *_argv;
	char **new_argv, *mailbox = NULL, *alt_char = NULL;
	char *p, *dup, new_flags[5];
	int max_argc, src, dest, i, j;
	bool flag_f = FALSE, flag_R = FALSE, flag_m, flag_C, has_arg;

	p = strrchr(argv[0], '/');
	if (p == NULL) p = argv[0];
	if (strstr(p, "dsync") == NULL)
		return;

	/* @UNSAFE: this is called when the "doveadm" binary is called as
	   "dsync" (for backwards compatibility) */
	max_argc = argc + 5;
	new_argv = calloc(sizeof(char *), max_argc);
	new_argv[0] = argv[0];
	dest = 1;
	getopt_str = master_service_getopt_string();

	/* add global doveadm flags */
	for (src = 1; src < argc; src++) {
		if (argv[src][0] != '-')
			break;

		flag_m = FALSE; flag_C = FALSE; has_arg = FALSE;
		dup = strdup(argv[src]);
		for (i = j = 1; argv[src][i] != '\0'; i++) {
			switch (argv[src][i]) {
			case 'C':
				flag_C = TRUE;
				break;
			case 'f':
				flag_f = TRUE;
				break;
			case 'R':
				flag_R = TRUE;
				break;
			case 'm':
				flag_m = TRUE;
				break;
			default:
				p = strchr(getopt_str, argv[src][i]);
				if (p != NULL && p[1] == ':')
					has_arg = TRUE;
				dup[j++] = argv[src][i];
				break;
			}
		}
		if (j > 1) {
			dup[j++] = '\0';
			new_argv[dest++] = dup;
			if (has_arg && src+1 < argc)
				new_argv[dest++] = argv[++src];
		}
		if (flag_m) {
			if (src+1 == argc)
				i_fatal("-m missing parameter");
			mailbox = argv[++src];
		}
		if (flag_C) {
			if (src+1 == argc)
				i_fatal("-C missing parameter");
			alt_char = argv[++src];
		}
	}
	if (alt_char != NULL) {
		new_argv[dest++] = "-o";
		new_argv[dest++] =
			p_strconcat(pool_datastack_create(),
				    "dsync_alt_char=", alt_char, NULL);
	}

	new_argv[dest++] = "dsync";
	if (src < argc) {
		/* mirror|backup|server */
		if (strcmp(argv[src], "dsync") == 0) {
			/* looks like we executed doveconf, which
			   re-executed ourself with new parameters.
			   no need to change them anymore. */
			return;
		}
		new_argv[dest++] = argv[src++];
	}

	/* dsync flags */
	new_flags[0] = '-'; i = 1;
	if (flag_f)
		new_flags[i++] = 'f';
	if (flag_R)
		new_flags[i++] = 'R';
	if (mailbox != NULL)
		new_flags[i++] = 'm';
	i_assert((unsigned int)i < sizeof(new_flags));
	new_flags[i] = '\0';

	if (i > 1) {
		new_argv[dest++] = strdup(new_flags);
		if (mailbox != NULL)
			new_argv[dest++] = mailbox;
	}

	/* rest of the parameters */
	for (; src < argc; src++)
		new_argv[dest++] = argv[src];
	i_assert(dest < max_argc);
	new_argv[dest] = NULL;

	*_argc = dest;
	*_argv = new_argv;
	optind = 1;
}
