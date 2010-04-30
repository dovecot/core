/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

struct list_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	struct mail_search_args *search_args;
};

static void
cmd_list_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct list_cmd_context *ctx = (struct list_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	iter = doveadm_mail_list_iter_init(user, ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) {
		printf("%s\n", info->name);
	}
	doveadm_mail_list_iter_deinit(&iter);
}

struct doveadm_mail_cmd_context *cmd_list(const char *const args[])
{
	struct list_cmd_context *ctx;
	struct mail_search_arg *arg;
	unsigned int i;

	ctx = doveadm_mail_cmd_init(struct list_cmd_context);
	ctx->ctx.run = cmd_list_run;

	ctx->search_args = mail_search_build_init();
	for (i = 0; args[i] != NULL; i++) {
		arg = mail_search_build_add(ctx->search_args,
					    SEARCH_MAILBOX_GLOB);
		arg->value.str = p_strdup(ctx->search_args->pool, args[i]);
	}
	if (i > 1) {
		struct mail_search_arg *subargs = ctx->search_args->args;

		ctx->search_args->args = NULL;
		arg = mail_search_build_add(ctx->search_args, SEARCH_OR);
		arg->value.subargs = subargs;
	}
	return &ctx->ctx;
}
