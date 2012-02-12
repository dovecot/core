/* Copyright (c) 2011-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "doveadm-print.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct move_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	const char *destname;
};

static int
cmd_move_box(struct move_cmd_context *ctx, struct mailbox *destbox,
	     const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_transaction_context *trans;
	struct mailbox_transaction_context *desttrans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	int ret = 0;

	if (doveadm_mail_iter_init(&ctx->ctx, info, ctx->ctx.search_args, 0,
				   NULL, &trans, &iter) < 0)
		return -1;

	/* use a separately committed transaction for each mailbox.
	   this guarantees that mails aren't expunged without actually having
	   been copied. */
	desttrans = mailbox_transaction_begin(destbox,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	while (doveadm_mail_iter_next(iter, &mail)) {
		save_ctx = mailbox_save_alloc(desttrans);
		mailbox_save_copy_flags(save_ctx, mail);
		if (mailbox_copy(&save_ctx, mail) == 0)
			mail_expunge(mail);
		else {
			i_error("Copying message UID %u from '%s' failed: %s",
				mail->uid, info->name,
				mailbox_get_last_error(destbox, NULL));
			doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
			ret = -1;
		}
	}

	if (mailbox_transaction_commit(&desttrans) < 0) {
		i_error("Committing moved mails failed: %s",
			mailbox_get_last_error(destbox, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
		/* rollback expunges */
		doveadm_mail_iter_deinit_rollback(&iter);
		ret = -1;
	} else {
		if (doveadm_mail_iter_deinit_sync(&iter) < 0)
			ret = -1;
	}
	return ret;
}

static int
cmd_move_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct move_cmd_context *ctx = (struct move_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	struct mail_namespace *ns;
	struct mailbox *destbox;
	const struct mailbox_info *info;
	int ret = 0;

	ns = mail_namespace_find(user->namespaces, ctx->destname);
	if (ns == NULL) {
		i_fatal_status(DOVEADM_EX_NOTFOUND,
			       "Can't find namespace for: %s", ctx->destname);
	}

	destbox = mailbox_alloc(ns->list, ctx->destname, MAILBOX_FLAG_SAVEONLY);
	if (mailbox_open(destbox) < 0) {
		i_error("Can't open mailbox '%s': %s", ctx->destname,
			mailbox_get_last_error(destbox, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
		mailbox_free(&destbox);
		return -1;
	}

	iter = doveadm_mailbox_list_iter_init(_ctx, user, _ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_move_box(ctx, destbox, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;

	if (mailbox_sync(destbox, 0) < 0) {
		i_error("Syncing mailbox '%s' failed: %s", ctx->destname,
			mailbox_get_last_error(destbox, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
		ret = -1;
	}
	mailbox_free(&destbox);
	return ret;

}

static void cmd_move_init(struct doveadm_mail_cmd_context *_ctx,
			  const char *const args[])
{
	struct move_cmd_context *ctx = (struct move_cmd_context *)_ctx;
	const char *destname = args[0];

	if (destname == NULL || args[1] == NULL)
		doveadm_mail_help_name("move");

	ctx->destname = p_strdup(ctx->ctx.pool, destname);
	ctx->ctx.search_args = doveadm_mail_build_search_args(args + 1);
	expunge_search_args_check(ctx->ctx.search_args, "move");
}

static struct doveadm_mail_cmd_context *cmd_move_alloc(void)
{
	struct move_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct move_cmd_context);
	ctx->ctx.v.init = cmd_move_init;
	ctx->ctx.v.run = cmd_move_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_move = {
	cmd_move_alloc, "move", "<destination> <search query>"
};
