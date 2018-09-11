/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-dot.h"
#include "istream-seekable.h"
#include "str.h"
#include "unichar.h"
#include "module-dir.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"
#include "mail-storage-hooks.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mailbox-list-iter.h"
#include "doveadm.h"
#include "client-connection.h"
#include "doveadm-settings.h"
#include "doveadm-print.h"
#include "doveadm-dsync.h"
#include "doveadm-mail.h"

#include <stdio.h>

#define DOVEADM_MAIL_CMD_INPUT_TIMEOUT_MSECS (5*60*1000)

ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;
void (*hook_doveadm_mail_init)(struct doveadm_mail_cmd_context *ctx);
struct doveadm_mail_cmd_module_register
	doveadm_mail_cmd_module_register = { 0 };
char doveadm_mail_cmd_hide = '\0';

static int killed_signo = 0;

bool doveadm_is_killed(void)
{
	return killed_signo != 0;
}

int doveadm_killed_signo(void)
{
	return killed_signo;
}

void doveadm_mail_failed_error(struct doveadm_mail_cmd_context *ctx,
			       enum mail_error error)
{
	int exit_code = EX_TEMPFAIL;

	switch (error) {
	case MAIL_ERROR_NONE:
		i_unreached();
	case MAIL_ERROR_TEMP:
	case MAIL_ERROR_UNAVAILABLE:
		break;
	case MAIL_ERROR_NOTPOSSIBLE:
	case MAIL_ERROR_EXISTS:
	case MAIL_ERROR_CONVERSION:
	case MAIL_ERROR_INVALIDDATA:
		exit_code = DOVEADM_EX_NOTPOSSIBLE;
		break;
	case MAIL_ERROR_PARAMS:
		exit_code = EX_USAGE;
		break;
	case MAIL_ERROR_PERM:
		exit_code = EX_NOPERM;
		break;
	case MAIL_ERROR_NOQUOTA:
		exit_code = EX_CANTCREAT;
		break;
	case MAIL_ERROR_NOTFOUND:
		exit_code = DOVEADM_EX_NOTFOUND;
		break;
	case MAIL_ERROR_EXPUNGED:
	case MAIL_ERROR_INUSE:
		break;
	case MAIL_ERROR_LIMIT:
		exit_code = DOVEADM_EX_NOTPOSSIBLE;
		break;
	case MAIL_ERROR_LOOKUP_ABORTED:
		break;
	}
	/* tempfail overrides all other exit codes, otherwise use whatever
	   error happened first */
	if (ctx->exit_code == 0 || exit_code == EX_TEMPFAIL)
		ctx->exit_code = exit_code;
}

void doveadm_mail_failed_storage(struct doveadm_mail_cmd_context *ctx,
				 struct mail_storage *storage)
{
	enum mail_error error;

	mail_storage_get_last_error(storage, &error);
	doveadm_mail_failed_error(ctx, error);
}

void doveadm_mail_failed_mailbox(struct doveadm_mail_cmd_context *ctx,
				 struct mailbox *box)
{
	doveadm_mail_failed_storage(ctx, mailbox_get_storage(box));
}

void doveadm_mail_failed_list(struct doveadm_mail_cmd_context *ctx,
			      struct mailbox_list *list)
{
	enum mail_error error;

	mailbox_list_get_last_error(list, &error);
	doveadm_mail_failed_error(ctx, error);
}

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_alloc_size(size_t size)
{
	struct doveadm_mail_cmd_context *ctx;
	pool_t pool;

	i_assert(size >= sizeof(struct doveadm_mail_cmd_context));

	pool = pool_alloconly_create("doveadm mail cmd", 1024);
	ctx = p_malloc(pool, size);
	ctx->pool = pool;
	ctx->cmd_input_fd = -1;
	return ctx;
}

static int
cmd_purge_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;
	int ret = 0;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != MAIL_NAMESPACE_TYPE_PRIVATE ||
		    ns->alias_for != NULL)
			continue;

		storage = mail_namespace_get_default_storage(ns);
		if (mail_storage_purge(storage) < 0) {
			i_error("Purging namespace '%s' failed: %s", ns->prefix,
				mail_storage_get_last_internal_error(storage, NULL));
			doveadm_mail_failed_storage(ctx, storage);
			ret = -1;
		}
	}
	return ret;
}

static struct doveadm_mail_cmd_context *cmd_purge_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_purge_run;
	return ctx;
}

static void doveadm_mail_cmd_input_input(struct doveadm_mail_cmd_context *ctx)
{
	const unsigned char *data;
	size_t size;

	while (i_stream_read_more(ctx->cmd_input, &data, &size) > 0)
		i_stream_skip(ctx->cmd_input, size);
	if (!ctx->cmd_input->eof)
		return;

	if (ctx->cmd_input->stream_errno != 0) {
		i_error("read(%s) failed: %s",
			i_stream_get_name(ctx->cmd_input),
			i_stream_get_error(ctx->cmd_input));
	}
	io_loop_stop(current_ioloop);
}

static void doveadm_mail_cmd_input_timeout(struct doveadm_mail_cmd_context *ctx)
{
	struct istream *input;

	input = i_stream_create_error_str(ETIMEDOUT, "Timed out in %u secs",
			DOVEADM_MAIL_CMD_INPUT_TIMEOUT_MSECS/1000);
	i_stream_set_name(input, i_stream_get_name(ctx->cmd_input));
	i_stream_destroy(&ctx->cmd_input);
	ctx->cmd_input = input;
	ctx->exit_code = EX_TEMPFAIL;
	io_loop_stop(current_ioloop);
}

static void doveadm_mail_cmd_input_read(struct doveadm_mail_cmd_context *ctx)
{
	struct ioloop *ioloop;
	struct io *io;
	struct timeout *to;

	ioloop = io_loop_create();
	/* Read the pending input from stream. Delay adding the IO in case
	   we're reading from a file. That would cause a panic with epoll. */
	io_loop_set_running(ioloop);
	doveadm_mail_cmd_input_input(ctx);
	if (io_loop_is_running(ioloop)) {
		io = io_add(ctx->cmd_input_fd, IO_READ,
			    doveadm_mail_cmd_input_input, ctx);
		to = timeout_add(DOVEADM_MAIL_CMD_INPUT_TIMEOUT_MSECS,
				 doveadm_mail_cmd_input_timeout, ctx);
		io_loop_run(ioloop);
		io_remove(&io);
		timeout_remove(&to);
	}
	io_loop_destroy(&ioloop);

	i_assert(ctx->cmd_input->eof);
	i_stream_seek(ctx->cmd_input, 0);
}

void doveadm_mail_get_input(struct doveadm_mail_cmd_context *ctx)
{
	const struct doveadm_cmd_context *cctx = ctx->cctx;
	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	struct istream *inputs[2];

	if (ctx->cmd_input != NULL)
		return;

	if (!cli && cctx->input == NULL) {
		ctx->cmd_input = i_stream_create_error_str(EINVAL, "Input stream missing (provide with file parameter)");
		return;
	}

	if (!cli)
		inputs[0] = i_stream_create_dot(cctx->input, FALSE);
	else {
		inputs[0] = i_stream_create_fd(STDIN_FILENO, 1024*1024);
		i_stream_set_name(inputs[0], "stdin");
	}
	inputs[1] = NULL;
	ctx->cmd_input_fd = i_stream_get_fd(inputs[0]);
	ctx->cmd_input = i_stream_create_seekable_path(inputs, 1024*256,
						       "/tmp/doveadm.");
	i_stream_set_name(ctx->cmd_input, i_stream_get_name(inputs[0]));
	i_stream_unref(&inputs[0]);

	doveadm_mail_cmd_input_read(ctx);
}

struct mailbox *
doveadm_mailbox_find(struct mail_user *user, const char *mailbox)
{
	struct mail_namespace *ns;

	if (!uni_utf8_str_is_valid(mailbox)) {
		i_fatal_status(EX_DATAERR,
			       "Mailbox name not valid UTF-8: %s", mailbox);
	}

	ns = mail_namespace_find(user->namespaces, mailbox);
	return mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_IGNORE_ACLS);
}

struct mail_search_args *
doveadm_mail_build_search_args(const char *const args[])
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *error, *charset = "UTF-8";

	parser = mail_search_parser_init_cmdline(args);
	if (mail_search_build(mail_search_register_get_human(),
			      parser, &charset, &sargs, &error) < 0)
		i_fatal("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

static int cmd_force_resync_box(struct doveadm_mail_cmd_context *ctx,
				const struct mailbox_info *info)
{
	struct mailbox *box;
	int ret = 0;

	box = mailbox_alloc(info->ns->list, info->vname,
			    MAILBOX_FLAG_IGNORE_ACLS);
	mailbox_set_reason(box, ctx->cmd->name);
	if (mailbox_open(box) < 0) {
		i_error("Opening mailbox %s failed: %s", info->vname,
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		ret = -1;
	} else if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC |
				MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) < 0) {
		i_error("Forcing a resync on mailbox %s failed: %s",
			info->vname, mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int cmd_force_resync_prerun(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
				   struct mail_storage_service_user *service_user,
				   const char **error_r)
{
	if (mail_storage_service_user_set_setting(service_user,
						  "mailbox_list_index_very_dirty_syncs",
						  "no",
						  error_r) <= 0)
		i_unreached();
	return 0;
}

static int cmd_force_resync_run(struct doveadm_mail_cmd_context *ctx,
				struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
		MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	const enum mail_namespace_type ns_mask = MAIL_NAMESPACE_TYPE_MASK_ALL;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = mailbox_list_iter_init_namespaces(user->namespaces, ctx->args,
						 ns_mask, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) == 0) T_BEGIN {
			if (cmd_force_resync_box(ctx, info) < 0)
				ret = -1;
		} T_END;
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Listing mailboxes failed: %s",
			mailbox_list_get_last_internal_error(user->namespaces->list, NULL));
		doveadm_mail_failed_list(ctx, user->namespaces->list);
		ret = -1;
	}
	return ret;
}

static void
cmd_force_resync_init(struct doveadm_mail_cmd_context *_ctx ATTR_UNUSED,
		      const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("force-resync");
}

static struct doveadm_mail_cmd_context *cmd_force_resync_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_force_resync_init;
	ctx->v.run = cmd_force_resync_run;
	ctx->v.prerun = cmd_force_resync_prerun;
	return ctx;
}

static void
doveadm_cctx_to_storage_service_input(const struct doveadm_cmd_context *cctx,
					struct mail_storage_service_input *input_r)
{
	i_zero(input_r);
	input_r->service = "doveadm";
	input_r->remote_ip = cctx->remote_ip;
	input_r->remote_port = cctx->remote_port;
	input_r->local_ip = cctx->local_ip;
	input_r->local_port = cctx->local_port;
	input_r->username = cctx->username;
}

static int
doveadm_mail_next_user(struct doveadm_mail_cmd_context *ctx,
		       const char **error_r)
{
	const struct doveadm_cmd_context *cctx = ctx->cctx;
	struct mail_storage_service_input input;
	const char *error, *ip;
	int ret;

	i_assert(cctx != NULL);

	ip = net_ip2addr(&cctx->remote_ip);
	if (ip[0] == '\0')
		i_set_failure_prefix("doveadm(%s): ", cctx->username);
	else
		i_set_failure_prefix("doveadm(%s,%s): ", ip, cctx->username);
	doveadm_cctx_to_storage_service_input(cctx, &input);
	if (ctx->cmd_input != NULL)
		i_stream_seek(ctx->cmd_input, 0);

	/* see if we want to execute this command via (another)
	   doveadm server */
	ret = doveadm_mail_server_user(ctx, &input, error_r);
	if (ret != 0)
		return ret;

	ret = mail_storage_service_lookup(ctx->storage_service, &input,
					  &ctx->cur_service_user, &error);
	if (ret <= 0) {
		if (ret < 0) {
			*error_r = t_strdup_printf("User lookup failed: %s",
						   error);
		}
		return ret;
	}

	if (ctx->v.prerun != NULL) {
		if (ctx->v.prerun(ctx, ctx->cur_service_user, error_r) < 0) {
			mail_storage_service_user_unref(&ctx->cur_service_user);
			return -1;
		}
	}

	ret = mail_storage_service_next(ctx->storage_service,
					ctx->cur_service_user,
					&ctx->cur_mail_user, error_r);
	if (ret < 0) {
		mail_storage_service_user_unref(&ctx->cur_service_user);
		return ret;
	}

	if (ctx->v.run(ctx, ctx->cur_mail_user) < 0) {
		i_assert(ctx->exit_code != 0);
	}
	mail_user_unref(&ctx->cur_mail_user);
	mail_storage_service_user_unref(&ctx->cur_service_user);
	return 1;
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	killed_signo = si->si_signo;
}

int doveadm_mail_single_user(struct doveadm_mail_cmd_context *ctx,
			     const char **error_r)
{
	const struct doveadm_cmd_context *cctx = ctx->cctx;

	i_assert(cctx->username != NULL);

	doveadm_cctx_to_storage_service_input(cctx, &ctx->storage_service_input);
	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 ctx->service_flags);
	ctx->v.init(ctx, ctx->args);
	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	lib_signals_set_handler(SIGINT, 0, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, 0, sig_die, NULL);

	return doveadm_mail_next_user(ctx, error_r);
}

static void
doveadm_mail_all_users(struct doveadm_mail_cmd_context *ctx,
		       const char *wildcard_user)
{
	struct doveadm_cmd_context *cctx = ctx->cctx;
	unsigned int user_idx;
	const char *ip, *user, *error;
	int ret;

	ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	doveadm_cctx_to_storage_service_input(cctx, &ctx->storage_service_input);
	ctx->storage_service = mail_storage_service_init(master_service, NULL,
							 ctx->service_flags);
        lib_signals_set_handler(SIGINT, 0, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, 0, sig_die, NULL);

	ctx->v.init(ctx, ctx->args);

	mail_storage_service_all_init_mask(ctx->storage_service,
		wildcard_user != NULL ? wildcard_user : "");

	if (hook_doveadm_mail_init != NULL)
		hook_doveadm_mail_init(ctx);

	user_idx = 0;
	while ((ret = ctx->v.get_next_user(ctx, &user)) > 0) {
		if (wildcard_user != NULL) {
			if (!wildcard_match_icase(user, wildcard_user))
				continue;
		}
		cctx->username = user;
		doveadm_print_sticky("username", user);
		T_BEGIN {
			ret = doveadm_mail_next_user(ctx, &error);
			if (ret < 0)
				i_error("%s", error);
			else if (ret == 0)
				i_info("User no longer exists, skipping");
		} T_END;
		if (ret == -1)
			break;
		if (doveadm_verbose) {
			if (++user_idx % 100 == 0) {
				printf("\r%d", user_idx);
				fflush(stdout);
			}
		}
		if (killed_signo != 0) {
			i_warning("Killed with signal %d", killed_signo);
			ret = -1;
			break;
		}
	}
	if (doveadm_verbose)
		printf("\n");
	ip = net_ip2addr(&cctx->remote_ip);
	if (ip[0] == '\0')
		i_set_failure_prefix("doveadm: ");
	else
		i_set_failure_prefix("doveadm(%s): ", ip);
	if (ret < 0) {
		i_error("Failed to iterate through some users");
		ctx->exit_code = EX_TEMPFAIL;
	}
}

static void
doveadm_mail_cmd_init_noop(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			   const char *const args[] ATTR_UNUSED)
{
}

static int
doveadm_mail_cmd_get_next_user(struct doveadm_mail_cmd_context *ctx,
			       const char **username_r)
{
	if (ctx->users_list_input == NULL)
		return mail_storage_service_all_next(ctx->storage_service, username_r);

	*username_r = i_stream_read_next_line(ctx->users_list_input);
	if (ctx->users_list_input->stream_errno != 0) {
		i_error("read(%s) failed: %s",
			i_stream_get_name(ctx->users_list_input),
			i_stream_get_error(ctx->users_list_input));
		return -1;
	}
	return *username_r != NULL ? 1 : 0;
}

static void
doveadm_mail_cmd_deinit_noop(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED)
{
}

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_init(const struct doveadm_mail_cmd *cmd,
		      const struct doveadm_settings *set)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = cmd->alloc();
	ctx->set = set;
	ctx->cmd = cmd;
	if (ctx->v.init == NULL)
		ctx->v.init = doveadm_mail_cmd_init_noop;
	if (ctx->v.get_next_user == NULL)
		ctx->v.get_next_user = doveadm_mail_cmd_get_next_user;
	if (ctx->v.deinit == NULL)
		ctx->v.deinit = doveadm_mail_cmd_deinit_noop;

	p_array_init(&ctx->module_contexts, ctx->pool, 5);
	return ctx;
}

static struct doveadm_mail_cmd_context *
doveadm_mail_cmdline_init(const struct doveadm_mail_cmd *cmd)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_init(cmd, doveadm_settings);
	ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	if (doveadm_debug)
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;
	return ctx;
}

static void
doveadm_mail_cmd_exec(struct doveadm_mail_cmd_context *ctx,
		      const char *wildcard_user)
{
	const struct doveadm_cmd_context *cctx = ctx->cctx;
	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	int ret;
	const char *error;

	if (ctx->v.preinit != NULL)
		ctx->v.preinit(ctx);

	ctx->iterate_single_user =
		!ctx->iterate_all_users && wildcard_user == NULL;
	if (doveadm_print_is_initialized() &&
	    (!ctx->iterate_single_user || ctx->add_username_header)) {
		doveadm_print_header("username", "Username",
				     DOVEADM_PRINT_HEADER_FLAG_STICKY |
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	}

	if (ctx->iterate_single_user) {
		if (cctx->username == NULL)
			i_fatal_status(EX_USAGE, "USER environment is missing and -u option not used");
		if (!cli) {
			/* we may access multiple users */
			ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP;
		}

		if (ctx->add_username_header)
			doveadm_print_sticky("username", cctx->username);
		ret = doveadm_mail_single_user(ctx, &error);
		if (ret < 0) {
			/* user lookup/init failed somehow */
			doveadm_exit_code = EX_TEMPFAIL;
			i_error("%s", error);
		} else if (ret == 0) {
			doveadm_exit_code = EX_NOUSER;
			i_error("User doesn't exist");
		}
	} else {
		ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP;
		doveadm_mail_all_users(ctx, wildcard_user);
	}
	if (ctx->search_args != NULL)
		mail_search_args_unref(&ctx->search_args);
	doveadm_mail_server_flush();
	ctx->v.deinit(ctx);
	doveadm_print_flush();

	/* service deinit unloads mail plugins, so do it late */
	mail_storage_service_deinit(&ctx->storage_service);

	if (ctx->exit_code != 0)
		doveadm_exit_code = ctx->exit_code;
}

static void doveadm_mail_cmd_free(struct doveadm_mail_cmd_context *ctx)
{
	i_stream_unref(&ctx->users_list_input);
	i_stream_unref(&ctx->cmd_input);
	pool_unref(&ctx->pool);
}

static void
doveadm_mail_cmd(const struct doveadm_mail_cmd *cmd, int argc, char *argv[])
{
	struct doveadm_cmd_context cctx;
	struct doveadm_mail_cmd_context *ctx;
	const char *getopt_args, *wildcard_user;
	int c;

	i_zero(&cctx);
	cctx.conn_type = DOVEADM_CONNECTION_TYPE_CLI;
	cctx.username = getenv("USER");

	ctx = doveadm_mail_cmdline_init(cmd);
	ctx->cctx = &cctx;
	ctx->full_args = (const void *)(argv + 1);

	getopt_args = "AF:S:u:";
	/* keep context's getopt_args first in case it contains '+' */
	if (ctx->getopt_args != NULL)
		getopt_args = t_strconcat(ctx->getopt_args, getopt_args, NULL);
	i_assert(master_getopt_str_is_valid(getopt_args));

	wildcard_user = NULL;
	while ((c = getopt(argc, argv, getopt_args)) > 0) {
		switch (c) {
		case 'A':
			ctx->iterate_all_users = TRUE;
			break;
		case 'S':
			doveadm_settings->doveadm_socket_path = optarg;
			if (doveadm_settings->doveadm_worker_count == 0)
				doveadm_settings->doveadm_worker_count = 1;
			break;
		case 'u':
			ctx->service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			cctx.username = optarg;
			if (strchr(cctx.username, '*') != NULL ||
			    strchr(cctx.username, '?') != NULL) {
				wildcard_user = cctx.username;
				cctx.username = NULL;
			}
			break;
		case 'F':
			ctx->service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			wildcard_user = "*";
			ctx->users_list_input =
				i_stream_create_file(optarg, 1024);
			break;
		default:
			if (ctx->v.parse_arg == NULL ||
			    !ctx->v.parse_arg(ctx, c))
				doveadm_mail_help(cmd);
		}
	}
	argv += optind;
	if (argv[0] != NULL && cmd->usage_args == NULL) {
		i_fatal_status(EX_USAGE, "doveadm %s: Unknown parameter: %s",
			       cmd->name, argv[0]);
	}
	ctx->args = (const void *)argv;
	doveadm_mail_cmd_exec(ctx, wildcard_user);
	doveadm_mail_cmd_free(ctx);
}

static bool
doveadm_mail_cmd_try_find_multi_word(const struct doveadm_mail_cmd *cmd,
				     const char *cmdname, int *argc,
				     const char *const **argv)
{
	size_t len;

	if (*argc < 2)
		return FALSE;
	*argc -= 1;
	*argv += 1;

	len = strlen((*argv)[0]);
	if (!str_begins(cmdname, (*argv)[0]))
		return FALSE;

	if (cmdname[len] == ' ') {
		/* more args */
		return doveadm_mail_cmd_try_find_multi_word(cmd, cmdname + len + 1,
							    argc, argv);
	}
	if (cmdname[len] != '\0')
		return FALSE;

	/* match */
	return TRUE;
}

const struct doveadm_mail_cmd *
doveadm_mail_cmd_find_from_argv(const char *cmd_name, int *argc,
				const char *const **argv)
{
	const struct doveadm_mail_cmd *cmd;
	size_t cmd_name_len;
	const char *const *orig_argv;
	int orig_argc;

	i_assert(*argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd = cmd->name + cmd_name_len + 1;

			orig_argc = *argc;
			orig_argv = *argv;
			if (doveadm_mail_cmd_try_find_multi_word(cmd, subcmd,
								 argc, argv))
				return cmd;
			*argc = orig_argc;
			*argv = orig_argv;
		}
	}

	return NULL;
}

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_mail_cmd *cmd;

	cmd = doveadm_mail_cmd_find_from_argv(cmd_name, &argc, (void *)&argv);
	if (cmd == NULL)
		return FALSE;
	doveadm_mail_cmd(cmd, argc, argv);
	return TRUE;
}

void doveadm_mail_register_cmd(const struct doveadm_mail_cmd *cmd)
{
	/* for now we'll just assume that cmd will be permanently in memory */
	array_append(&doveadm_mail_cmds, cmd, 1);
}

const struct doveadm_mail_cmd *doveadm_mail_cmd_find(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;
	}
	return NULL;
}

void doveadm_mail_usage(string_t *out)
{
	const struct doveadm_mail_cmd *cmd;

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (cmd->usage_args == &doveadm_mail_cmd_hide)
			continue;
		str_printfa(out, "%s\t"DOVEADM_CMD_MAIL_USAGE_PREFIX, cmd->name);
		if (cmd->usage_args != NULL)
			str_append(out, cmd->usage_args);
		str_append_c(out, '\n');
	}
}

void doveadm_mail_help(const struct doveadm_mail_cmd *cmd)
{
	fprintf(stderr, "doveadm %s "DOVEADM_CMD_MAIL_USAGE_PREFIX" %s\n",
		cmd->name, cmd->usage_args == NULL ? "" : cmd->usage_args);
	exit(EX_USAGE);
}

void doveadm_mail_try_help_name(const char *cmd_name)
{
	const struct doveadm_cmd_ver2 *cmd2;
	const struct doveadm_mail_cmd *cmd;

	cmd2 = doveadm_cmd_find_ver2(cmd_name);
	if (cmd2 != NULL)
		help_ver2(cmd2);

	cmd = doveadm_mail_cmd_find(cmd_name);
	if (cmd != NULL)
		doveadm_mail_help(cmd);
}

bool doveadm_mail_has_subcommands(const char *cmd_name)
{
	const struct doveadm_mail_cmd *cmd;
	size_t len = strlen(cmd_name);

	array_foreach(&doveadm_mail_cmds, cmd) {
		if (strncmp(cmd->name, cmd_name, len) == 0 &&
		    cmd->name[len] == ' ')
			return TRUE;
	}
	return FALSE;
}

void doveadm_mail_help_name(const char *cmd_name)
{
	doveadm_mail_try_help_name(cmd_name);
	i_fatal("Missing help for command %s", cmd_name);
}

static struct doveadm_cmd_ver2 doveadm_cmd_force_resync_ver2 = {
	.name = "force-resync",
	.mail_cmd = cmd_force_resync_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox mask>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

static struct doveadm_cmd_ver2 doveadm_cmd_purge_ver2 = {
	.name = "purge",
	.mail_cmd = cmd_purge_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAMS_END
};


static struct doveadm_mail_cmd *mail_commands[] = {
	&cmd_batch,
	&cmd_dsync_backup,
	&cmd_dsync_mirror,
	&cmd_dsync_server
};

static struct doveadm_cmd_ver2 *mail_commands_ver2[] = {
	&doveadm_cmd_mailbox_metadata_set_ver2,
	&doveadm_cmd_mailbox_metadata_unset_ver2,
	&doveadm_cmd_mailbox_metadata_get_ver2,
	&doveadm_cmd_mailbox_metadata_list_ver2,
	&doveadm_cmd_mailbox_status_ver2,
	&doveadm_cmd_mailbox_list_ver2,
	&doveadm_cmd_mailbox_create_ver2,
	&doveadm_cmd_mailbox_delete_ver2,
	&doveadm_cmd_mailbox_rename_ver2,
	&doveadm_cmd_mailbox_subscribe_ver2,
	&doveadm_cmd_mailbox_unsubscribe_ver2,
	&doveadm_cmd_mailbox_update_ver2,
	&doveadm_cmd_mailbox_path_ver2,
	&doveadm_cmd_fetch_ver2,
	&doveadm_cmd_save_ver2,
	&doveadm_cmd_index_ver2,
	&doveadm_cmd_altmove_ver2,
	&doveadm_cmd_deduplicate_ver2,
	&doveadm_cmd_expunge_ver2,
	&doveadm_cmd_flags_add_ver2,
	&doveadm_cmd_flags_remove_ver2,
	&doveadm_cmd_flags_replace_ver2,
	&doveadm_cmd_import_ver2,
	&doveadm_cmd_force_resync_ver2,
	&doveadm_cmd_purge_ver2,
	&doveadm_cmd_search_ver2,
	&doveadm_cmd_copy_ver2,
	&doveadm_cmd_move_ver2,
	&doveadm_cmd_mailbox_cache_decision,
	&doveadm_cmd_mailbox_cache_remove,
	&doveadm_cmd_mailbox_cache_purge,
	&doveadm_cmd_rebuild_attachments,
};

void doveadm_mail_init(void)
{
	struct module_dir_load_settings mod_set;
	unsigned int i;

	i_array_init(&doveadm_mail_cmds, 32);
	for (i = 0; i < N_ELEMENTS(mail_commands); i++)
		doveadm_mail_register_cmd(mail_commands[i]);

	for (i = 0; i < N_ELEMENTS(mail_commands_ver2); i++)
		doveadm_cmd_register_ver2(mail_commands_ver2[i]);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = doveadm_debug;
	mod_set.binary_name = "doveadm";

	/* load all configured mail plugins */
	mail_storage_service_modules =
		module_dir_load_missing(mail_storage_service_modules,
					doveadm_settings->mail_plugin_dir,
					doveadm_settings->mail_plugins,
					&mod_set);
	/* keep mail_storage_init() referenced so that its _deinit() doesn't
	   try to free doveadm plugins' hooks too early. */
	mail_storage_init();
}

void doveadm_mail_deinit(void)
{
	mail_storage_deinit();
	array_free(&doveadm_mail_cmds);
}

void
doveadm_cmd_ver2_to_mail_cmd_wrapper(struct doveadm_cmd_context *cctx)
{
	struct doveadm_mail_cmd_context *mctx;
	const char *wildcard_user;
	const char *fieldstr;
	ARRAY_TYPE(const_string) pargv, full_args;
	int i;
	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	bool tcp_server = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_TCP);
	struct doveadm_mail_cmd mail_cmd = {
		cctx->cmd->mail_cmd, cctx->cmd->name, cctx->cmd->usage
	};

	if (!cli) {
		mctx = doveadm_mail_cmd_init(&mail_cmd, doveadm_settings);
		/* doveadm-server always does userdb lookups */
		mctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	} else {
		mctx = doveadm_mail_cmdline_init(&mail_cmd);
	}
	mctx->cctx = cctx;
	mctx->iterate_all_users = FALSE;
	wildcard_user = NULL;
	p_array_init(&full_args, mctx->pool, 8);
	p_array_init(&pargv, mctx->pool, 8);

	for(i=0;i<cctx->argc;i++) {
		const struct doveadm_cmd_param *arg = &cctx->argv[i];

		if (!arg->value_set)
			continue;

		if (strcmp(arg->name, "all-users") == 0) {
			if (tcp_server)
				mctx->add_username_header = TRUE;
			else
				mctx->iterate_all_users = arg->value.v_bool;
			fieldstr = "-A";
			array_append(&full_args, &fieldstr, 1);
		} else if (strcmp(arg->name, "socket-path") == 0) {
			doveadm_settings->doveadm_socket_path = arg->value.v_string;
			if (doveadm_settings->doveadm_worker_count == 0)
				doveadm_settings->doveadm_worker_count = 1;
		} else if (strcmp(arg->name, "user") == 0) {
			mctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			if (!tcp_server)
				cctx->username = arg->value.v_string;

			fieldstr = "-u";
			array_append(&full_args, &fieldstr, 1);
			array_append(&full_args, &arg->value.v_string, 1);
			if (strchr(arg->value.v_string, '*') != NULL ||
			    strchr(arg->value.v_string, '?') != NULL) {
				if (tcp_server)
					mctx->add_username_header = TRUE;
				else {
					wildcard_user = arg->value.v_string;
					cctx->username = NULL;
				}
			}
		} else if (strcmp(arg->name, "user-file") == 0) {
			mctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			wildcard_user = "*";
			mctx->users_list_input = arg->value.v_istream;
			fieldstr = "-F";
			array_append(&full_args, &fieldstr, 1);
			fieldstr = ""; /* value doesn't really matter */
			array_append(&full_args, &fieldstr, 1);
			i_stream_ref(mctx->users_list_input);
		} else if (strcmp(arg->name, "field") == 0 ||
			   strcmp(arg->name, "flag") == 0) {
			/* mailbox status, fetch, flags: convert an array into a
			   single space-separated parameter (alternative to
			   fieldstr) */
			fieldstr = p_array_const_string_join(mctx->pool,
					&arg->value.v_array, " ");
			array_append(&pargv, &fieldstr, 1);
		} else if (strcmp(arg->name, "file") == 0) {
			/* input for doveadm_mail_get_input(),
			   used by e.g. save */
			if (mctx->cmd_input != NULL) {
				i_error("Only one file input allowed: %s", arg->name);
				doveadm_mail_cmd_free(mctx);
				doveadm_exit_code = EX_USAGE;
				return;
			}
			mctx->cmd_input = arg->value.v_istream;
			i_stream_ref(mctx->cmd_input);

		/* Keep all named special parameters above this line */

		} else if (mctx->v.parse_arg != NULL && arg->short_opt != '\0') {
			const char *short_opt_str = p_strdup_printf(
				mctx->pool, "-%c", arg->short_opt);

			switch(arg->type) {
			case CMD_PARAM_BOOL:
				optarg = NULL;
				break;
			case CMD_PARAM_INT64:
				optarg = (char*)dec2str(arg->value.v_int64);
				break;
			case CMD_PARAM_IP:
				optarg = (char*)net_ip2addr(&arg->value.v_ip);
				break;
			case CMD_PARAM_STR:
				optarg = (char*)arg->value.v_string;
				break;
			default:
				i_panic("Cannot convert parameter %s to short opt",
					arg->name);
			}
			if (!mctx->v.parse_arg(mctx, arg->short_opt)) {
				i_error("Invalid parameter %c", arg->short_opt);
				doveadm_mail_cmd_free(mctx);
				doveadm_exit_code = EX_USAGE;
				return;
			}

			array_append(&full_args, &short_opt_str, 1);
			if (arg->type == CMD_PARAM_STR)
				array_append(&full_args, &arg->value.v_string, 1);
		} else if ((arg->flags & CMD_PARAM_FLAG_POSITIONAL) != 0) {
			/* feed this into pargv */
			if (arg->type == CMD_PARAM_ARRAY)
				array_append_array(&pargv, &arg->value.v_array);
			else if (arg->type == CMD_PARAM_STR)
				array_append(&pargv, &arg->value.v_string, 1);
		} else {
			doveadm_exit_code = EX_USAGE;
			i_error("invalid parameter: %s", arg->name);
			doveadm_mail_cmd_free(mctx);
			return;
		}
	}

	const char *dashdash = "--";
	array_append(&full_args, &dashdash, 1);

	array_append_zero(&pargv);
	/* All the -parameters need to be included in full_args so that
	   they're sent to doveadm-server. */
	unsigned int args_pos = array_count(&full_args);
	array_append_array(&full_args, &pargv);

	mctx->args = array_idx(&full_args, args_pos);
	mctx->full_args = array_idx(&full_args, 0);

	doveadm_mail_cmd_exec(mctx, wildcard_user);
	doveadm_mail_cmd_free(mctx);
}
