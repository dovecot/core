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
#include "mailbox-list.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "dsync-brain.h"
#include "dsync-slave.h"
#include "doveadm-dsync.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

struct dsync_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum dsync_brain_sync_type sync_type;
	const char *mailbox, *namespace_prefix;

	const char *remote_name;
	const char *local_location;

	int fd_in, fd_out, fd_err;
	struct io *io_err;

	unsigned int lock_timeout;

	unsigned int lock:1;
	unsigned int default_replica_location:1;
	unsigned int reverse_backup:1; //FIXME
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
	array_append_zero(&cmd_args);
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
	array_append_zero(&cmd_args);
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

static int
cmd_dsync_run_local(struct dsync_cmd_context *ctx, struct mail_user *user,
		    struct dsync_brain *brain, struct dsync_slave *slave2)
{
	struct dsync_brain *brain2;
	struct mail_user *user2;
	struct setting_parser_context *set_parser;
	const char *set_line, *path1, *path2;
	bool brain1_running, brain2_running, changed1, changed2;

	i_assert(ctx->local_location != NULL);

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
	path1 = mailbox_list_get_root_path(user->namespaces->list,
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	path2 = mailbox_list_get_root_path(user2->namespaces->list,
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (path1 != NULL && path2 != NULL &&
	    strcmp(path1, path2) == 0) {
		i_fatal("Both source and destination mail_location "
			"points to same directory: %s", path1);
	}

	brain2 = dsync_brain_slave_init(user2, slave2);

	brain1_running = brain2_running = TRUE;
	changed1 = changed2 = TRUE;
	while (brain1_running || brain2_running) {
		if (dsync_brain_has_failed(brain) ||
		    dsync_brain_has_failed(brain2))
			break;

		i_assert(changed1 || changed2);
		brain1_running = dsync_brain_run(brain, &changed1);
		brain2_running = dsync_brain_run(brain2, &changed2);
	}
	mail_user_unref(&user2);
	return dsync_brain_deinit(&brain2);
}

static void
cmd_dsync_run_remote(struct mail_user *user)
{
	i_set_failure_prefix(t_strdup_printf("dsync-local(%s): ",
					     user->username));
	io_loop_run(current_ioloop);
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

static int
cmd_dsync_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct dsync_cmd_context *ctx = (struct dsync_cmd_context *)_ctx;
	struct dsync_slave *slave, *slave2 = NULL;
	struct dsync_brain *brain;
	struct mail_namespace *sync_ns = NULL;
	int ret = 0;

	user->admin = TRUE;
	user->dsyncing = TRUE;

	if (ctx->namespace_prefix != NULL) {
		sync_ns = mail_namespace_find(user->namespaces,
					      ctx->namespace_prefix);
		if (sync_ns == NULL) {
			i_fatal("Namespace prefix=%s doesn't exist",
				ctx->namespace_prefix);
		}
	}

	if (!ctx->remote)
		dsync_slave_init_pipe(&slave, &slave2);
	else {
		string_t *temp_prefix = t_str_new(64);
		mail_user_set_get_temp_prefix(temp_prefix, user->set);
		slave = dsync_slave_init_io(ctx->fd_in, ctx->fd_out,
					    ctx->remote_name,
					    str_c(temp_prefix));
	}

	if (doveadm_debug || doveadm_verbose) {
		// FIXME
	}
	brain = dsync_brain_master_init(user, slave, sync_ns,
					ctx->sync_type,
					DSYNC_BRAIN_FLAG_MAILS_HAVE_GUIDS |
					DSYNC_BRAIN_FLAG_SEND_REQUESTS,
					"");

	if (!ctx->remote) {
		if (cmd_dsync_run_local(ctx, user, brain, slave2) < 0)
			_ctx->exit_code = EX_TEMPFAIL;
	} else {
		cmd_dsync_run_remote(user);
	}

	if (dsync_brain_deinit(&brain) < 0)
		_ctx->exit_code = EX_TEMPFAIL;
	dsync_slave_deinit(&slave);
	if (slave2 != NULL)
		dsync_slave_deinit(&slave2);
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
	ctx->remote_name = "remote";

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
		ctx->remote_name = ctx->local_location+7;
		remote_cmd_args = parse_ssh_location(ctx, ctx->remote_name,
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
		ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_FULL;
		break;
	case 'm':
		ctx->mailbox = optarg;
		break;
	case 'n':
		ctx->namespace_prefix = optarg;
		break;
	case 'R':
		ctx->reverse_backup = TRUE;
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
	ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_CHANGED;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_dsync_backup_alloc(void)
{
	struct doveadm_mail_cmd_context *_ctx;
	struct dsync_cmd_context *ctx;

	_ctx = cmd_dsync_alloc();
	ctx = (struct dsync_cmd_context *)_ctx;
	//FIXME
	return _ctx;
}

static int
cmd_dsync_server_run(struct doveadm_mail_cmd_context *_ctx ATTR_UNUSED,
		     struct mail_user *user)
{
	struct dsync_slave *slave;
	struct dsync_brain *brain;
	string_t *temp_prefix;

	user->admin = TRUE;
	user->dsyncing = TRUE;

	i_set_failure_prefix(t_strdup_printf("dsync-remote(%s): ",
					     user->username));

	temp_prefix = t_str_new(64);
	mail_user_set_get_temp_prefix(temp_prefix, user->set);

	slave = dsync_slave_init_io(STDIN_FILENO, STDOUT_FILENO,
				    "local", str_c(temp_prefix));
	brain = dsync_brain_slave_init(user, slave);

	io_loop_run(current_ioloop);

	dsync_slave_deinit(&slave);
	return dsync_brain_deinit(&brain);
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
	ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_CHANGED;
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
	bool dsync_server = FALSE;

	p = strrchr(argv[0], '/');
	if (p == NULL) p = argv[0];
	if (strstr(p, "dsync") == NULL)
		return;

	/* @UNSAFE: this is called when the "doveadm" binary is called as
	   "dsync" (for backwards compatibility) */
	max_argc = argc + 7;
	new_argv = t_new(char *, max_argc);
	new_argv[0] = argv[0];
	dest = 1;
	getopt_str = master_service_getopt_string();

	/* add global doveadm flags */
	for (src = 1; src < argc; src++) {
		if (argv[src][0] != '-')
			break;

		flag_m = FALSE; flag_C = FALSE; has_arg = FALSE; flag_u = FALSE;
		dup = t_strdup_noconst(argv[src]);
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
	else if (strcmp(argv[src], "server") == 0) {
		new_argv[dest] = "dsync-server";
		dsync_server = TRUE;
	} else
		i_fatal("Invalid parameter: %s", argv[src]);
	src++; dest++;

	if (src < argc && strncmp(argv[src], "-E", 2) == 0) {
		/* we're re-executing dsync due to doveconf */
		return;
	}

	/* dsync flags */
	new_flags[0] = '-';
	new_flags[1] = 'E'; i = 2;
	if (!dsync_server) {
		if (flag_f)
			new_flags[i++] = 'f';
		if (flag_R)
			new_flags[i++] = 'R';
		if (mailbox != NULL)
			new_flags[i++] = 'm';
	}
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
