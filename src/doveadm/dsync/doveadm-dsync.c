/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "execv-const.h"
#include "str.h"
#include "var-expand.h"
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

#define DSYNC_LOCK_FILENAME ".dovecot-sync.lock"

struct dsync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum dsync_brain_flags brain_flags;
	const char *mailbox, *namespace_prefix;

	const char *local_location;

	int fd_in, fd_out, fd_err;
	struct io *io_err;

	unsigned int lock_timeout;

	unsigned int lock:1;
	unsigned int default_replica_location:1;
	unsigned int reverse_workers:1;
	unsigned int remote:1;
};

static bool legacy_dsync = FALSE;

static void remote_error_input(struct dsync_cmd_context *ctx)
{
	char buf[1024];
	ssize_t ret;

	ret = read(ctx->fd_err, buf, sizeof(buf)-1);
	if (ret == -1) {
		io_remove(&ctx->io_err);
		return;
	}
	if (ret > 0) {
		buf[ret-1] = '\0';
		i_error("remote: %s", buf);
	}
}

static void
run_cmd(struct dsync_cmd_context *ctx, const char *const *args)
{
	int fd_in[2], fd_out[2], fd_err[2];

	if (pipe(fd_in) < 0 || pipe(fd_out) < 0 || pipe(fd_err) < 0)
		i_fatal("pipe() failed: %m");

	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child, which will execute the proxy server. stdin/stdout
		   goes to pipes which we'll pass to proxy client. */
		if (dup2(fd_in[0], STDIN_FILENO) < 0 ||
		    dup2(fd_out[1], STDOUT_FILENO) < 0 ||
		    dup2(fd_err[1], STDERR_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		(void)close(fd_in[0]);
		(void)close(fd_in[1]);
		(void)close(fd_out[0]);
		(void)close(fd_out[1]);
		(void)close(fd_err[0]);
		(void)close(fd_err[1]);

		execvp_const(args[0], args);
	default:
		/* parent */
		break;
	}

	(void)close(fd_in[0]);
	(void)close(fd_out[1]);
	(void)close(fd_err[1]);
	ctx->fd_in = fd_out[0];
	ctx->fd_out = fd_in[1];
	ctx->fd_err = fd_err[0];
	ctx->io_err = io_add(ctx->fd_err, IO_READ, remote_error_input, ctx);
}

static void
mirror_get_remote_cmd_line(const char *const *argv,
			   const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	unsigned int i;
	const char *p;

	i_assert(argv[0] != NULL);

	t_array_init(&cmd_args, 16);
	for (i = 0; argv[i] != NULL; i++) {
		p = argv[i];
		array_append(&cmd_args, &p, 1);
	}

	if (legacy_dsync) {
		/* we're executing dsync */
		p = "server";
	} else {
		/* we're executing doveadm */
		p = "dsync-server";
	}
	array_append(&cmd_args, &p, 1);
	(void)array_append_space(&cmd_args);
	*cmd_args_r = array_idx(&cmd_args, 0);
}

static const char *const *
get_ssh_cmd_args(struct dsync_cmd_context *ctx,
		 const char *host, const char *login, const char *mail_user)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ '\0', NULL, "login" },
		{ '\0', NULL, "host" },
		{ '\0', NULL, "lock_timeout" },
		{ '\0', NULL, "namespace" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	ARRAY_TYPE(const_string) cmd_args;
	string_t *str, *str2;
	const char *value, *const *args;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = mail_user;
	tab[1].value = login;
	tab[2].value = host;
	tab[3].value = dec2str(ctx->lock_timeout);
	tab[4].value = ctx->namespace_prefix;

	t_array_init(&cmd_args, 8);
	str = t_str_new(128);
	str2 = t_str_new(128);
	args = t_strsplit(doveadm_settings->dsync_remote_cmd, " ");
	for (; *args != NULL; args++) {
		if (strchr(*args, '%') == NULL)
			value = *args;
		else {
			/* some automation: if parameter's all %variables
			   expand to empty, but the %variable isn't the only
			   text in the parameter, skip it. */
			str_truncate(str, 0);
			str_truncate(str2, 0);
			var_expand(str, *args, tab);
			var_expand(str2, *args, static_tab);
			if (strcmp(str_c(str), str_c(str2)) == 0 &&
			    str_len(str) > 0)
				continue;
			value = t_strdup(str_c(str));
		}
		array_append(&cmd_args, &value, 1);
	}
	(void)array_append_space(&cmd_args);
	return array_idx(&cmd_args, 0);
}

static bool mirror_get_remote_cmd(struct dsync_cmd_context *ctx,
				  const char *user,
				  const char *const **cmd_args_r)
{
	const char *p, *host, *const *argv = ctx->ctx.args;

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
	*cmd_args_r = get_ssh_cmd_args(ctx, host, "", user);
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

	worker2 = dsync_worker_init_local(user2, ctx->namespace_prefix,
					  *ctx->ctx.set->dsync_alt_char);
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

static const char *const *
parse_ssh_location(struct dsync_cmd_context *ctx,
		   const char *location, const char *username)
{
	const char *host, *login;

	host = strchr(location, '@');
	if (host != NULL)
		login = t_strdup_until(location, host++);
	else {
		host = location;
		login = "";
	}
	return get_ssh_cmd_args(ctx, host, login, username);
}

static int dsync_lock(struct mail_user *user, unsigned int lock_timeout,
		      const char **path_r, struct file_lock **lock_r)
{
	const char *home, *path;
	int ret, fd;

	if ((ret = mail_user_get_home(user, &home)) < 0) {
		i_error("Couldn't look up user's home dir");
		return -1;
	}
	if (ret == 0) {
		i_error("User has no home directory");
		return -1;
	}

	path = t_strconcat(home, "/"DSYNC_LOCK_FILENAME, NULL);
	fd = creat(path, 0600);
	if (fd == -1) {
		i_error("Couldn't create lock %s: %m", path);
		return -1;
	}

	if (file_wait_lock(fd, path, F_WRLCK, FILE_LOCK_METHOD_FCNTL,
			   lock_timeout, lock_r) <= 0) {
		i_error("Couldn't lock %s: %m", path);
		(void)close(fd);
		return -1;
	}
	*path_r = path;
	return fd;
}

static int
cmd_dsync_start(struct dsync_cmd_context *ctx, struct dsync_worker *worker1,
		struct dsync_worker *worker2)
{
	struct dsync_brain *brain;

	/* create and run the brain */
	brain = dsync_brain_init(worker1, worker2, ctx->mailbox,
				 ctx->brain_flags);
	if (!ctx->remote)
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
		ctx->ctx.exit_code = 2;
	}
	if (dsync_brain_deinit(&brain) < 0) {
		ctx->ctx.exit_code = EX_TEMPFAIL;
		return -1;
	}
	return 0;
}

static int
cmd_dsync_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	struct dsync_worker *worker1, *worker2, *workertmp;
	const char *lock_path;
	struct file_lock *lock;
	int lock_fd, ret = 0;

	user->admin = TRUE;

	/* create workers */
	worker1 = dsync_worker_init_local(user, ctx->namespace_prefix,
					  *_ctx->set->dsync_alt_char);
	if (!ctx->remote)
		worker2 = cmd_dsync_run_local(ctx, user);
	else
		worker2 = cmd_dsync_run_remote(ctx, user);
	if (ctx->reverse_workers) {
		workertmp = worker1;
		worker1 = worker2;
		worker2 = workertmp;
	}

	if (!ctx->lock)
		ret = cmd_dsync_start(ctx, worker1, worker2);
	else {
		lock_fd = dsync_lock(user, ctx->lock_timeout, &lock_path, &lock);
		if (lock_fd == -1) {
			_ctx->exit_code = EX_TEMPFAIL;
			ret = -1;
		} else {
			ret = cmd_dsync_start(ctx, worker1, worker2);
			file_lock_free(&lock);
			if (close(lock_fd) < 0)
				i_error("close(%s) failed: %m", lock_path);
		}
	}
	dsync_worker_deinit(&worker1);
	dsync_worker_deinit(&worker2);
	if (ctx->io_err != NULL)
		io_remove(&ctx->io_err);
	if (ctx->fd_err != -1) {
		(void)close(ctx->fd_err);
		ctx->fd_err = -1;
	}
	return ret;
}

static int cmd_dsync_prerun(struct doveadm_mail_cmd_context *_ctx,
			    struct mail_storage_service_user *service_user,
			    const char **error_r)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	const char *const *remote_cmd_args = NULL;
	const struct mail_user_settings *user_set;
	const char *username = "";

	user_set = mail_storage_service_user_get_set(service_user)[0];

	ctx->fd_in = STDIN_FILENO;
	ctx->fd_out = STDOUT_FILENO;
	ctx->fd_err = -1;
	ctx->remote = FALSE;

	if (ctx->default_replica_location) {
		ctx->local_location =
			mail_user_set_plugin_getenv(user_set, "mail_replica");
		if (ctx->local_location == NULL ||
		    *ctx->local_location == '\0') {
			*error_r = "User has no mail_replica in userdb";
			_ctx->exit_code = DOVEADM_EX_NOTFOUND;
			return -1;
		}
	} else {
		/* if we're executing remotely, give -u parameter if we also
		   did a userdb lookup. */
		if ((_ctx->service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0)
			username = _ctx->cur_username;

		if (!mirror_get_remote_cmd(ctx, username, &remote_cmd_args)) {
			/* it's a mail_location */
			if (_ctx->args[1] != NULL)
				doveadm_mail_help_name(_ctx->cmd->name);
			ctx->local_location = _ctx->args[0];
		}
	}

	if (remote_cmd_args == NULL && ctx->local_location != NULL &&
	    strncmp(ctx->local_location, "remote:", 7) == 0) {
		/* this is a remote (ssh) command */
		remote_cmd_args = parse_ssh_location(ctx, ctx->local_location+7,
						     _ctx->cur_username);
	}

	if (remote_cmd_args != NULL) {
		/* do this before mail_storage_service_next() in case it
		   drops process privileges */
		run_cmd(ctx, remote_cmd_args);
		ctx->remote = TRUE;
	}
	return 0;
}

static void cmd_dsync_init(struct doveadm_mail_cmd_context *_ctx,
			   const char *const args[])
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;

	if (ctx->default_replica_location) {
		if (args[0] != NULL)
			i_error("Don't give mail location with -d parameter");
	} else {
		if (args[0] == NULL)
			doveadm_mail_help_name(_ctx->cmd->name);
	}

	lib_signals_ignore(SIGHUP, TRUE);

	if (doveadm_debug || doveadm_verbose)
		ctx->brain_flags |= DSYNC_BRAIN_FLAG_VERBOSE;
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
	case 'd':
		ctx->default_replica_location = TRUE;
		break;
	case 'E':
		/* dsync wrapper detection flag */
		legacy_dsync = TRUE;
		break;
	case 'f':
		ctx->brain_flags |= DSYNC_BRAIN_FLAG_FULL_SYNC;
		break;
	case 'l':
		ctx->lock = TRUE;
		if (str_to_uint(optarg, &ctx->lock_timeout) < 0)
			i_error("Invalid -l parameter: %s", optarg);
		break;
	case 'm':
		ctx->mailbox = optarg;
		break;
	case 'n':
		ctx->namespace_prefix = optarg;
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
	ctx->ctx.getopt_args = "+dEfl:m:n:R";
	ctx->ctx.v.parse_arg = cmd_mailbox_dsync_parse_arg;
	ctx->ctx.v.preinit = cmd_dsync_preinit;
	ctx->ctx.v.init = cmd_dsync_init;
	ctx->ctx.v.prerun = cmd_dsync_prerun;
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

static int
cmd_dsync_server_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	struct dsync_proxy_server *server;
	struct dsync_worker *worker;
	struct file_lock *lock;
	const char *lock_path;
	int lock_fd, ret = 0;

	user->admin = TRUE;

	i_set_failure_prefix(t_strdup_printf("dsync-remote(%s): ",
					     user->username));
	worker = dsync_worker_init_local(user, ctx->namespace_prefix,
					 *_ctx->set->dsync_alt_char);
	server = dsync_proxy_server_init(STDIN_FILENO, STDOUT_FILENO, worker);

	if (!ctx->lock)
		io_loop_run(current_ioloop);
	else {
		lock_fd = dsync_lock(user, ctx->lock_timeout, &lock_path, &lock);
		if (lock_fd == -1) {
			_ctx->exit_code = EX_TEMPFAIL;
			ret = -1;
		} else {
			io_loop_run(current_ioloop);
			file_lock_free(&lock);
			if (close(lock_fd) < 0)
				i_error("close(%s) failed: %m", lock_path);
		}
	}

	dsync_proxy_server_deinit(&server);
	dsync_worker_deinit(&worker);
	return ret;
}

static bool
cmd_mailbox_dsync_server_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;

	switch (c) {
	case 'E':
		/* dsync wrapper detection flag */
		legacy_dsync = TRUE;
		break;
	case 'l':
		ctx->lock = TRUE;
		if (str_to_uint(optarg, &ctx->lock_timeout) < 0)
			i_error("Invalid -l parameter: %s", optarg);
		break;
	case 'n':
		ctx->namespace_prefix = optarg;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_dsync_server_alloc(void)
{
	struct dsync_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct dsync_cmd_context);
	ctx->ctx.getopt_args = "El:n:";
	ctx->ctx.v.parse_arg = cmd_mailbox_dsync_server_parse_arg;
	ctx->ctx.v.run = cmd_dsync_server_run;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_dsync_mirror = {
	cmd_dsync_alloc, "sync",
	"[-dfR] [-l <secs>] [-m <mailbox>] [-n <namespace>] <dest>"
};
struct doveadm_mail_cmd cmd_dsync_backup = {
	cmd_dsync_backup_alloc, "backup",
	"[-dfR] [-l <secs>] [-m <mailbox>] [-n <namespace>] <dest>"
};
struct doveadm_mail_cmd cmd_dsync_server = {
	cmd_dsync_server_alloc, "dsync-server", &doveadm_mail_cmd_hide
};

void doveadm_dsync_main(int *_argc, char **_argv[])
{
	int argc = *_argc;
	const char *getopt_str;
	char **argv = *_argv;
	char **new_argv, *mailbox = NULL, *alt_char = NULL, *username = NULL;
	char *p, *dup, new_flags[6];
	int max_argc, src, dest, i, j;
	bool flag_f = FALSE, flag_R = FALSE, flag_m, flag_u, flag_C, has_arg;

	p = strrchr(argv[0], '/');
	if (p == NULL) p = argv[0];
	if (strstr(p, "dsync") == NULL)
		return;

	/* @UNSAFE: this is called when the "doveadm" binary is called as
	   "dsync" (for backwards compatibility) */
	max_argc = argc + 7;
	new_argv = calloc(sizeof(char *), max_argc);
	new_argv[0] = argv[0];
	dest = 1;
	getopt_str = master_service_getopt_string();

	/* add global doveadm flags */
	for (src = 1; src < argc; src++) {
		if (argv[src][0] != '-')
			break;

		flag_m = FALSE; flag_C = FALSE; has_arg = FALSE; flag_u = FALSE;
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
			case 'u':
				flag_u = TRUE;
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
		if (flag_u) {
			if (src+1 == argc)
				i_fatal("-u missing parameter");
			username = argv[++src];
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

	/* mirror|backup|server */
	if (src == argc)
		i_fatal("Missing mirror or backup parameter");
	if (strcmp(argv[src], "sync") == 0 ||
	    strcmp(argv[src], "dsync-server") == 0) {
		/* we're re-executing dsync due to doveconf.
		   "backup" re-exec detection is later. */
		return;
	}
	if (strcmp(argv[src], "mirror") == 0)
		new_argv[dest] = "sync";
	else if (strcmp(argv[src], "backup") == 0)
		new_argv[dest] = "backup";
	else if (strcmp(argv[src], "server") == 0)
		new_argv[dest] = "dsync-server";
	else
		i_fatal("Invalid parameter: %s", argv[src]);
	src++; dest++;

	if (src < argc && strncmp(argv[src], "-E", 2) == 0) {
		/* we're re-executing dsync due to doveconf */
		return;
	}

	/* dsync flags */
	new_flags[0] = '-';
	new_flags[1] = 'E'; i = 2;
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
	if (username != NULL) {
		new_argv[dest++] = "-u";
		new_argv[dest++] = username;
	}

	/* rest of the parameters */
	for (; src < argc; src++)
		new_argv[dest++] = argv[src];
	i_assert(dest < max_argc);
	new_argv[dest] = NULL;

	legacy_dsync = TRUE;
	*_argc = dest;
	*_argv = new_argv;
	optind = 1;
}
