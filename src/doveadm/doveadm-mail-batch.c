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
	struct doveadm_mail_cmd_context *cmd;
	int ret = 0;

	array_foreach_elem(&ctx->commands, cmd) {
		if (cmd->v.prerun != NULL &&
		    cmd->v.prerun(cmd, service_user, error_r) < 0) {
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
	struct doveadm_mail_cmd_context *cmd;
	int ret = 0;

	array_foreach_elem(&ctx->commands, cmd) {
		cmd->cur_mail_user = user;
		const char *reason_code =
			event_reason_code_prefix("doveadm", "cmd_",
						 cmd->cmd->name);
		struct event_reason *reason = event_reason_begin(reason_code);
		ret = cmd->v.run(cmd, user);
		event_reason_end(&reason);
		if (ret < 0) {
			i_assert(cmd->exit_code != 0);
			_ctx->exit_code = cmd->exit_code;
			break;
		}
		cmd->cur_mail_user = NULL;
	}
	return ret;
}

static void
cmd_batch_add(struct batch_cmd_context *batchctx,
	      int argc, const char *const *argv)
{
	struct doveadm_mail_cmd_context *subctx;
	const struct doveadm_cmd_ver2 *cmd_ver2;
	const struct doveadm_mail_cmd *cmd;
	const char *getopt_args;
	int c;

	cmd_ver2 = doveadm_cmdline_find_with_args(argv[0], &argc, &argv);
	if (cmd_ver2 == NULL)
		i_fatal_status(EX_USAGE, "doveadm batch: '%s' mail command doesn't exist", argv[0]);

	struct doveadm_mail_cmd *dyncmd =
		p_new(batchctx->ctx.pool, struct doveadm_mail_cmd, 1);
	dyncmd->usage_args = cmd_ver2->usage;
	dyncmd->name = cmd_ver2->name;
	dyncmd->alloc = cmd_ver2->mail_cmd;
	cmd = dyncmd;

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
			array_push_back(&sep_args, &args[i]);
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
	struct doveadm_mail_cmd_context *cmd;
	struct batch_cmd_context *subctx;

	array_foreach_elem(&ctx->commands, cmd) {
		subctx = (struct batch_cmd_context *)cmd;
		subctx->ctx.storage_service = _ctx->storage_service;
		if (subctx->ctx.v.init != NULL)
			subctx->ctx.v.init(&subctx->ctx, subctx->ctx.args);
	}
}

static void cmd_batch_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct batch_cmd_context *ctx = (struct batch_cmd_context *)_ctx;
	struct doveadm_mail_cmd_context *cmd;

	array_foreach_elem(&ctx->commands, cmd) {
		doveadm_mail_cmd_deinit(cmd);
		doveadm_mail_cmd_free(cmd);
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

struct doveadm_cmd_ver2 doveadm_cmd_batch = {
	.name = "batch",
	.mail_cmd = cmd_batch_alloc,
	.usage = "<sep> <cmd1> [<sep> <cmd2> [..]]",
	.flags = CMD_FLAG_NO_UNORDERED_OPTIONS,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "separator", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "args", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
