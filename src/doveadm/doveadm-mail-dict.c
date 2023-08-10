/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "doveadm-mail.h"
#include "doveadm-dict.h"
#include "doveadm-print.h"

struct mail_dict_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *key, *value, *prefix;
	int64_t inc_diff;
	enum dict_iterate_flags iter_flags;
};

static void cmd_mail_dict_get_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "key", &cctx->key)) {
		doveadm_mail_help_name("mail dict get");
		return;
	}
	doveadm_print_header("value", "", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static int cmd_mail_dict_get_run(struct doveadm_mail_cmd_context *_cctx,
				  struct mail_user *user ATTR_UNUSED)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	doveadm_dict_get(_cctx->cctx, cctx->key);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_dict_get_alloc(void)
{
	struct mail_dict_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_dict_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_dict_get_init;
	ctx->ctx.v.run = cmd_mail_dict_get_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

static void cmd_mail_dict_set_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "key", &cctx->key) ||
	    !doveadm_cmd_param_str(_cctx->cctx, "value", &cctx->value))
		doveadm_mail_help_name("mail dict set");
}

static int cmd_mail_dict_set_run(struct doveadm_mail_cmd_context *_cctx,
				 struct mail_user *user ATTR_UNUSED)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	doveadm_dict_set(_cctx->cctx, cctx->key, cctx->value);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_dict_set_alloc(void)
{
	struct mail_dict_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_dict_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_dict_set_init;
	ctx->ctx.v.run = cmd_mail_dict_set_run;
	return &ctx->ctx;
}

static void cmd_mail_dict_unset_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "key", &cctx->key))
		doveadm_mail_help_name("mail dict unset");
}

static int cmd_mail_dict_unset_run(struct doveadm_mail_cmd_context *_cctx,
				   struct mail_user *user ATTR_UNUSED)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	doveadm_dict_unset(_cctx->cctx, cctx->key);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_dict_unset_alloc(void)
{
	struct mail_dict_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_dict_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_dict_unset_init;
	ctx->ctx.v.run = cmd_mail_dict_unset_run;
	return &ctx->ctx;
}

static void cmd_mail_dict_inc_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "key", &cctx->key) ||
	    !doveadm_cmd_param_int64(_cctx->cctx, "difference", &cctx->inc_diff)) {
		doveadm_mail_help_name("mail dict inc");
		return;
	}
}

static int cmd_mail_dict_inc_run(struct doveadm_mail_cmd_context *_cctx,
				  struct mail_user *user ATTR_UNUSED)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	doveadm_dict_inc(_cctx->cctx, cctx->key, cctx->inc_diff);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_dict_inc_alloc(void)
{
	struct mail_dict_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_dict_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_dict_inc_init;
	ctx->ctx.v.run = cmd_mail_dict_inc_run;
	return &ctx->ctx;
}

static void cmd_mail_dict_iter_init(struct doveadm_mail_cmd_context *_cctx)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	if (!doveadm_cmd_param_str(_cctx->cctx, "prefix", &cctx->prefix)) {
		doveadm_mail_help_name("mail dict iter");
		return;
	}
	if (doveadm_cmd_param_flag(_cctx->cctx, "exact"))
		cctx->iter_flags |= DICT_ITERATE_FLAG_EXACT_KEY;
	if (doveadm_cmd_param_flag(_cctx->cctx, "recurse"))
		cctx->iter_flags |= DICT_ITERATE_FLAG_RECURSE;
	if (doveadm_cmd_param_flag(_cctx->cctx, "no-value"))
		cctx->iter_flags |= DICT_ITERATE_FLAG_NO_VALUE;

	doveadm_print_header_simple("key");
	if ((cctx->iter_flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		doveadm_print_header_simple("value");
}

static int cmd_mail_dict_iter_run(struct doveadm_mail_cmd_context *_cctx,
				  struct mail_user *user ATTR_UNUSED)
{
	struct mail_dict_cmd_context *cctx =
		container_of(_cctx, struct mail_dict_cmd_context, ctx);

	doveadm_dict_iter(_cctx->cctx, cctx->iter_flags, cctx->prefix);
	return 0;
}

static struct doveadm_mail_cmd_context *cmd_mail_dict_iter_alloc(void)
{
	struct mail_dict_cmd_context *ctx =
		doveadm_mail_cmd_alloc(struct mail_dict_cmd_context);
	ctx->ctx.service_flags |= MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT;
	ctx->ctx.v.init = cmd_mail_dict_iter_init;
	ctx->ctx.v.run = cmd_mail_dict_iter_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TAB);
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_mail_dict_get = {
	.name = "mail dict get",
	.mail_cmd = cmd_mail_dict_get_alloc,
	.usage = "<config-filter-name> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_dict_set = {
	.name = "mail dict set",
	.mail_cmd = cmd_mail_dict_set_alloc,
	.usage = "[-t <timestamp-nsecs>] [-e <expire-secs>] <config-filter-name> <key> <value>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('e', "expire-secs", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "value", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_dict_unset = {
	.name = "mail dict unset",
	.mail_cmd = cmd_mail_dict_unset_alloc,
	.usage = "[-t <timestamp-nsecs>] <config-filter-name> <key>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_dict_inc = {
	.name = "mail dict inc",
	.mail_cmd = cmd_mail_dict_inc_alloc,
	.usage = "[-t <timestamp-nsecs>] <config-filter-name> <key> <diff>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('t', "timestamp", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "key", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "difference", CMD_PARAM_INT64, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mail_dict_iter = {
	.name = "mail dict iter",
	.mail_cmd = cmd_mail_dict_iter_alloc,
	.usage = "[-1RV] <config-filter-name> <prefix>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('1', "exact", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('R', "recurse", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('V', "no-value", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "filter-name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "prefix", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
