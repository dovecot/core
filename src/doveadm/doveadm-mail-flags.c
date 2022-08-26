/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct flags_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	enum modify_type modify_type;
	enum mail_flags flags;
	const char *const *keywords;
};

static int
cmd_flags_run_box(struct flags_cmd_context *ctx,
		  const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	struct mailbox *box;
	struct mail *mail;
	struct mail_keywords *kw = NULL;

	int ret = doveadm_mail_iter_init(&ctx->ctx, info, ctx->ctx.search_args,
					 0, NULL, 0, &iter);
	if (ret <= 0)
		return ret;
	box = doveadm_mail_iter_get_mailbox(iter);

	if (ctx->keywords != NULL) {
		if (mailbox_keywords_create(box, ctx->keywords, &kw) < 0) {
			e_error(ctx->ctx.cctx->event, "Invalid keywords: %s",
				mailbox_get_last_internal_error(box, NULL));
			(void)doveadm_mail_iter_deinit(&iter);
			ctx->ctx.exit_code = DOVEADM_EX_NOTPOSSIBLE;
			return -1;
		}
	}

	while (doveadm_mail_iter_next(iter, &mail)) {
		mail_update_flags(mail, ctx->modify_type, ctx->flags);
		if (kw != NULL)
			mail_update_keywords(mail, ctx->modify_type, kw);
	}
	if (kw != NULL)
		mailbox_keywords_unref(&kw);
	return doveadm_mail_iter_deinit_sync(&iter);
}

static int
cmd_flags_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct flags_cmd_context *ctx =
		container_of(_ctx, struct flags_cmd_context, ctx);
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(_ctx, user, _ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_flags_run_box(ctx, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_flags_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct flags_cmd_context *ctx =
		container_of(_ctx, struct flags_cmd_context, ctx);

	enum mail_flags flag;
	ARRAY_TYPE(const_string) keywords;

	const char *const *flags = NULL;
	if (!doveadm_cmd_param_array(cctx, "flag", &flags)) {
		const char *flagstr;
		if (doveadm_cmd_param_str(cctx, "flagstr", &flagstr))
			flags = t_strsplit_spaces(flagstr, " ");
	}

	const char *const *query;
	if (flags == NULL || !doveadm_cmd_param_array(cctx, "query", &query)) {
		switch (ctx->modify_type) {
		case MODIFY_ADD:
			doveadm_mail_help_name("flags add");
		case MODIFY_REMOVE:
			doveadm_mail_help_name("flags remove");
		case MODIFY_REPLACE:
			doveadm_mail_help_name("flags replace");
		}
		i_unreached();
	}

	p_array_init(&keywords, _ctx->pool, 8);
	for (; *flags != NULL; flags++) {
		const char *str = *flags;

		if (str[0] == '\\') {
			flag = imap_parse_system_flag(str);
			if (flag == 0)
				i_fatal("Invalid system flag: %s", str);
			ctx->flags |= flag;
		} else {
			str = p_strdup(_ctx->pool, str);
			array_push_back(&keywords, &str);
		}
	}
	if (array_count(&keywords) > 0 || ctx->modify_type == MODIFY_REPLACE) {
		array_append_zero(&keywords);
		ctx->keywords = array_front(&keywords);
	}
	_ctx->search_args = doveadm_mail_build_search_args(query);
}

static struct doveadm_mail_cmd_context *
cmd_flag_alloc(enum modify_type modify_type)
{
	struct flags_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct flags_cmd_context);
	ctx->modify_type = modify_type;
	ctx->ctx.v.init = cmd_flags_init;
	ctx->ctx.v.run = cmd_flags_run;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_flags_add_alloc(void)
{
	return cmd_flag_alloc(MODIFY_ADD);
}

static struct doveadm_mail_cmd_context *cmd_flags_remove_alloc(void)
{
	return cmd_flag_alloc(MODIFY_REMOVE);
}

static struct doveadm_mail_cmd_context *cmd_flags_replace_alloc(void)
{
	return cmd_flag_alloc(MODIFY_REPLACE);
}

struct doveadm_cmd_ver2 doveadm_cmd_flags_add_ver2 = {
	.name = "flags add",
	.mail_cmd = cmd_flags_add_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<flags> <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "flag", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('\0', "flagstr", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_DO_NOT_EXPOSE)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_flags_remove_ver2 = {
	.name = "flags remove",
	.mail_cmd = cmd_flags_remove_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<flags> <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "flag", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('\0', "flagstr", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_DO_NOT_EXPOSE)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_flags_replace_ver2 = {
	.name = "flags replace",
	.mail_cmd = cmd_flags_replace_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<flags> <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "flag", CMD_PARAM_ARRAY, 0)
DOVEADM_CMD_PARAM('\0', "flagstr", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL|CMD_PARAM_FLAG_DO_NOT_EXPOSE)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
