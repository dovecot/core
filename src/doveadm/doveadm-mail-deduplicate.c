/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

struct deduplicate_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	bool by_msgid;
};

static int
cmd_deduplicate_box(struct doveadm_mail_cmd_context *_ctx,
		    const struct mailbox_info *info,
		    struct mail_search_args *search_args)
{
	struct deduplicate_cmd_context *ctx =
		container_of(_ctx, struct deduplicate_cmd_context, ctx);

	struct doveadm_mail_iter *iter;
	struct mail *mail;
	enum mail_error error;
	pool_t pool;
	HASH_TABLE(const char *, void *) hash;
	const char *key, *errstr;

	int ret = doveadm_mail_iter_init(_ctx, info, search_args, 0, NULL, 0,
					 &iter);
	if (ret <= 0)
		return ret;

	ret = 0;
	pool = pool_alloconly_create("deduplicate", 10240);
	hash_table_create(&hash, pool, 0, str_hash, strcmp);
	while (doveadm_mail_iter_next(iter, &mail)) {
		if (ctx->by_msgid) {
			if (mail_get_first_header(mail, "Message-ID", &key) < 0) {
				errstr = mail_get_last_internal_error(mail, &error);
				if (error == MAIL_ERROR_NOTFOUND)
					continue;
				e_error(ctx->ctx.cctx->event,
					"Couldn't lookup Message-ID: for UID=%u: %s",
					mail->uid, errstr);
				doveadm_mail_failed_error(_ctx, error);
				ret = -1;
				break;
			}
		} else {
			if (mail_get_special(mail, MAIL_FETCH_GUID, &key) < 0) {
				errstr = mail_get_last_internal_error(mail, &error);
				if (error == MAIL_ERROR_NOTFOUND)
					continue;
				e_error(ctx->ctx.cctx->event,
					"Couldn't lookup GUID: for UID=%u: %s",
					mail->uid, errstr);
				doveadm_mail_failed_error(_ctx, error);
				ret = -1;
				break;
			}
		}
		if (key != NULL && *key != '\0') {
			if (hash_table_lookup(hash, key) != NULL)
				mail_expunge(mail);
			else {
				key = p_strdup(pool, key);
				hash_table_insert(hash, key, POINTER_CAST(1));
			}
		}
	}

	if (doveadm_mail_iter_deinit_sync(&iter) < 0)
		ret = -1;

	hash_table_destroy(&hash);
	pool_unref(&pool);
	return ret;
}

static int
cmd_deduplicate_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	iter = doveadm_mailbox_list_iter_init(ctx, user, ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_deduplicate_box(ctx, info, ctx->search_args) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_deduplicate_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct deduplicate_cmd_context *ctx =
		container_of(_ctx, struct deduplicate_cmd_context, ctx);

	const char *const *query;
	ctx->by_msgid = doveadm_cmd_param_flag(cctx, "by-msgid");
	if (!doveadm_cmd_param_array(cctx, "query", &query))
		doveadm_mail_help_name("deduplicate");

	_ctx->search_args = doveadm_mail_build_search_args(query);
}

static struct doveadm_mail_cmd_context *cmd_deduplicate_alloc(void)
{
	struct deduplicate_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct deduplicate_cmd_context);
	ctx->ctx.v.init = cmd_deduplicate_init;
	ctx->ctx.v.run = cmd_deduplicate_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_deduplicate_ver2 = {
	.name = "deduplicate",
	.mail_cmd = cmd_deduplicate_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-m] <search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('m', "by-msgid", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
