/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "doveadm-print.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct copy_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	struct mail_storage_service_user *source_service_user;
	struct mail_user *source_user;

	const char *destname;
	bool move;
};

static int
cmd_copy_box(struct copy_cmd_context *ctx, struct mailbox *destbox,
	     const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_transaction_context *desttrans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	int ret = 0;

	if (doveadm_mail_iter_init(&ctx->ctx, info, ctx->ctx.search_args, 0,
				   NULL, &iter) < 0)
		return -1;

	/* use a separately committed transaction for each mailbox.
	   this guarantees that mails aren't expunged without actually having
	   been copied. */
	desttrans = mailbox_transaction_begin(destbox,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	while (doveadm_mail_iter_next(iter, &mail)) {
		save_ctx = mailbox_save_alloc(desttrans);
		mailbox_save_copy_flags(save_ctx, mail);
		if (mailbox_copy(&save_ctx, mail) == 0) {
			if (ctx->move)
				mail_expunge(mail);
		} else {
			i_error("Copying message UID %u from '%s' failed: %s",
				mail->uid, info->vname,
				mailbox_get_last_error(destbox, NULL));
			doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
			ret = -1;
		}
	}

	if (mailbox_transaction_commit(&desttrans) < 0) {
		i_error("Committing %s mails failed: %s",
			ctx->move ? "moved" : "copied",
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

static void
cmd_copy_alloc_source_user(struct copy_cmd_context *ctx, const char *username)
{
	struct mail_storage_service_input input;
	const char *error;

	input = ctx->ctx.storage_service_input;
	input.username = username;

	if (mail_storage_service_lookup_next(ctx->ctx.storage_service, &input,
					     &ctx->source_service_user,
					     &ctx->source_user,
					     &error) < 0)
		i_fatal("Couldn't lookup user %s: %s", input.username, error);
}

static int
cmd_copy_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct copy_cmd_context *ctx = (struct copy_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	struct mail_user *src_user;
	struct mail_namespace *ns;
	struct mailbox *destbox;
	const struct mailbox_info *info;
	int ret = 0;

	ns = mail_namespace_find(user->namespaces, ctx->destname);
	destbox = mailbox_alloc(ns->list, ctx->destname, MAILBOX_FLAG_SAVEONLY);
	if (mailbox_open(destbox) < 0) {
		i_error("Can't open mailbox '%s': %s", ctx->destname,
			mailbox_get_last_error(destbox, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, destbox);
		mailbox_free(&destbox);
		return -1;
	}

	src_user = ctx->source_user != NULL ? ctx->source_user : user;
	iter = doveadm_mailbox_list_iter_init(_ctx, src_user, _ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		if (cmd_copy_box(ctx, destbox, info) < 0)
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

static void cmd_copy_init(struct doveadm_mail_cmd_context *_ctx,
			  const char *const args[])
{
	struct copy_cmd_context *ctx = (struct copy_cmd_context *)_ctx;
	const char *destname = args[0], *cmdname = ctx->move ? "move" : "copy";

	if (destname == NULL || args[1] == NULL)
		doveadm_mail_help_name(cmdname);
	args++;

	if (args[0] != NULL && args[1] != NULL &&
	    strcasecmp(args[0], "user") == 0) {
		if ((_ctx->service_flags &
		     MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) == 0)
			i_fatal("Use -u parameter to specify destination user");

		cmd_copy_alloc_source_user(ctx, args[1]);
		args += 2;
	}

	ctx->destname = p_strdup(ctx->ctx.pool, destname);
	_ctx->search_args = doveadm_mail_build_search_args(args);
	expunge_search_args_check(ctx->ctx.search_args, cmdname);
}

static void cmd_copy_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct copy_cmd_context *ctx = (struct copy_cmd_context *)_ctx;

	if (ctx->source_user != NULL) {
		mail_storage_service_user_free(&ctx->source_service_user);
		mail_user_unref(&ctx->source_user);
	}
}

static struct doveadm_mail_cmd_context *cmd_copy_alloc(void)
{
	struct copy_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct copy_cmd_context);
	ctx->ctx.v.init = cmd_copy_init;
	ctx->ctx.v.deinit = cmd_copy_deinit;
	ctx->ctx.v.run = cmd_copy_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_move_alloc(void)
{
	struct copy_cmd_context *ctx;

	ctx = (struct copy_cmd_context *)cmd_copy_alloc();
	ctx->move = TRUE;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_copy = {
	cmd_copy_alloc, "copy", "<destination> [user <source user>] <search query>"
};
struct doveadm_mail_cmd cmd_move = {
	cmd_move_alloc, "move", "<destination> [user <source user>] <search query>"
};
