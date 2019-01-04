/* Copyright (c) 2012-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm-mail.h"

#include <unistd.h>

struct batch_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	ARRAY(struct doveadm_mail_cmd_context *) commands;
};

static int cmd_batch_prerun(struct doveadm_mail_cmd_context *_ctx,
			    struct mail_storage_service_user *service_user,
			    const char **error_r)
{
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	struct doveadm_mail_cmd_context *const *cmdp;
	int ret = 0;

	array_foreach(&ctx->commands, cmdp) {
		if ((*cmdp)->v.prerun != NULL &&
		    (*cmdp)->v.prerun(*cmdp, service_user, error_r) < 0) {
			ret = -1;
			break;
		}
	}
	return ret;
}

static int cmd_batch_run(struct doveadm_mail_cmd_context *_ctx,
			 struct mail_user *user)
{
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	struct doveadm_mail_cmd_context *const *cmdp;
	int ret = 0;

	array_foreach(&ctx->commands, cmdp) {
		(*cmdp)->cur_mail_user = user;
		if ((*cmdp)->v.run(*cmdp, user) < 0) {
			i_assert((*cmdp)->exit_code != 0);
			_ctx->exit_code = (*cmdp)->exit_code;
			ret = -1;
			break;
		}
		(*cmdp)->cur_mail_user = NULL;
	}
	return ret;
}

static void
cmd_batch_add(struct batch_cmd_context *batchctx,
	      int argc, const char *const *argv)
{
	struct doveadm_mail_cmd_context *subctx;
	const struct doveadm_cmd_ver2 *cmd_ver2;
	struct doveadm_mail_cmd tmpcmd;
	const struct doveadm_mail_cmd *cmd;
	const char *getopt_args;
	int c;

	cmd_ver2 = doveadm_cmd_find_with_args_ver2(argv[0], &argc, &argv);

	if (cmd_ver2 == NULL)
		cmd = doveadm_mail_cmd_find_from_argv(argv[0], &argc, &argv);
	else {
		i_zero(&tmpcmd);
		tmpcmd.usage_args = cmd_ver2->usage;
		tmpcmd.name = cmd_ver2->name;
		tmpcmd.alloc = cmd_ver2->mail_cmd;
		cmd = &tmpcmd;
	}

	if (cmd == NULL)
		i_fatal_status(EX_USAGE, "doveadm batch: '%s' mail command doesn't exist", argv[0]);

	subctx = doveadm_mail_cmd_init(cmd, doveadm_settings);
	subctx->full_args = argv + 1;
	subctx->service_flags |= batchctx->ctx.service_flags;

	i_getopt_reset();
	getopt_args = subctx->getopt_args != NULL ? subctx->getopt_args : "";
	while ((c = getopt(argc, (void *)argv, getopt_args)) > 0) {
		if (subctx->v.parse_arg == NULL ||
		    !subctx->v.parse_arg(subctx, c))
			doveadm_mail_help(cmd);
	}
	argv += optind;
	if (argv[0] != NULL && cmd->usage_args == NULL) {
		i_fatal_status(EX_USAGE, "doveadm %s: Unknown parameter: %s",
			       cmd->name, argv[0]);
	}
	subctx->args = argv;
	if (subctx->v.preinit != NULL)
		subctx->v.preinit(subctx);
	array_push_back(&batchctx->commands, &subctx);
}

static void
cmd_batch_preinit(struct doveadm_mail_cmd_context *_ctx)
{
	const char *const *args = _ctx->args;
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	ARRAY_TYPE(const_string) sep_args;
	const char *sep = args[0];
	unsigned int i, start;
	int argc;
	const char *const *argv;

	if (sep == NULL || args[1] == NULL)
		doveadm_mail_help_name("batch");
	args++;

	p_array_init(&ctx->commands, _ctx->pool, 8);
	p_array_init(&sep_args, _ctx->pool, 16);
	for (i = start = 0;; i++) {
		if (args[i] != NULL && strcmp(args[i], sep) != 0) {
			array_append(&sep_args, &args[i], 1);
			continue;
		}
		if (i > start) {
			(void)array_append_space(&sep_args);
			argc = i - start;
			argv = array_idx(&sep_args, start);
			cmd_batch_add(ctx, argc, argv);
			start = i+1;
		}
		if (args[i] == NULL)
			break;
	}
	(void)array_append_space(&sep_args);
}

static void
cmd_batch_init(struct doveadm_mail_cmd_context *_ctx,
	       const char *const args[] ATTR_UNUSED)
{
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	struct doveadm_mail_cmd_context *const *cmdp;
	struct batch_cmd_context *subctx;

	array_foreach(&ctx->commands, cmdp) {
		subctx = (struct batch_cmd_context *)*cmdp;
		subctx->ctx.storage_service = _ctx->storage_service;
		if (subctx->ctx.v.init != NULL)
			subctx->ctx.v.init(&subctx->ctx, subctx->ctx.args);
	}
}

static void cmd_batch_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	struct doveadm_mail_cmd_context *const *cmdp;

	array_foreach(&ctx->commands, cmdp) {
		if ((*cmdp)->v.deinit != NULL)
			(*cmdp)->v.deinit(*cmdp);
	}
}

static struct doveadm_mail_cmd_context *cmd_batch_alloc(void)
{
	struct batch_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct batch_cmd_context);
	ctx->ctx.getopt_args = "+"; /* disable processing -args in the middle */
	ctx->ctx.v.preinit = cmd_batch_preinit;
	ctx->ctx.v.init = cmd_batch_init;
	ctx->ctx.v.prerun = cmd_batch_prerun;
	ctx->ctx.v.run = cmd_batch_run;
	ctx->ctx.v.deinit = cmd_batch_deinit;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_batch = {
	cmd_batch_alloc, "batch", "<sep> <cmd1> [<sep> <cmd2> [..]]"
};
