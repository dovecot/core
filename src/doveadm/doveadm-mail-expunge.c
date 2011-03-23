/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

static int
cmd_expunge_box(const struct mailbox_info *info,
		struct mail_search_args *search_args)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_transaction_context *trans;
	struct mail *mail;

	if (doveadm_mail_iter_init(info, search_args, &trans, &iter) < 0)
		return -1;

	mail = mail_alloc(trans, 0, NULL);
	while (doveadm_mail_iter_next(iter, mail)) {
		if (doveadm_debug) {
			i_debug("expunge: box=%s uid=%u",
				info->name, mail->uid);
		}
		mail_expunge(mail);
	}
	mail_free(&mail);
	return doveadm_mail_iter_deinit_sync(&iter);
}

static bool
expunge_search_args_is_mailbox_ok(struct mail_search_arg *args);

static bool
expunge_search_args_is_mailbox_or_ok(struct mail_search_arg *args)
{
	struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_OR:
			if (!expunge_search_args_is_mailbox_or_ok(arg->value.subargs))
				return FALSE;
			break;
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (!expunge_search_args_is_mailbox_ok(arg->value.subargs))
				return FALSE;
			break;
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GUID:
		case SEARCH_MAILBOX_GLOB:
			break;
		default:
			return FALSE;
		}
	}
	return TRUE;
}

static bool
expunge_search_args_is_mailbox_ok(struct mail_search_arg *args)
{
	struct mail_search_arg *arg;
	bool have_or = FALSE;

	/* a) we find one mailbox here in the SUB block */
	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GUID:
		case SEARCH_MAILBOX_GLOB:
			return TRUE;
		case SEARCH_OR:
			have_or = TRUE;
			break;
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (expunge_search_args_is_mailbox_ok(arg->value.subargs))
				return TRUE;
			break;
		default:
			break;
		}
	}

	/* b) there is at least one OR block, and all of the ORs must have
	   mailbox */
	if (!have_or)
		return FALSE;

	for (arg = args; arg != NULL; arg = arg->next) {
		if (arg->type == SEARCH_OR &&
		    !expunge_search_args_is_mailbox_or_ok(arg->value.subargs))
			return FALSE;
	}
	return TRUE;
}

static bool
expunge_search_args_is_msgset_ok(struct mail_search_arg *args);

static bool
expunge_search_args_is_msgset_or_ok(struct mail_search_arg *args)
{
	struct mail_search_arg *arg;

	/* we're done if all OR branches contain something else besides
	   MAILBOXes */
	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GUID:
		case SEARCH_MAILBOX_GLOB:
			return FALSE;
		case SEARCH_OR:
			if (!expunge_search_args_is_msgset_or_ok(arg->value.subargs))
				return FALSE;
			break;
		case SEARCH_SUB:
			if (!expunge_search_args_is_msgset_ok(arg->value.subargs))
				return FALSE;
			break;
		default:
			break;
		}
	}
	return TRUE;
}

static bool
expunge_search_args_is_msgset_ok(struct mail_search_arg *args)
{
	struct mail_search_arg *arg;

	/* all args can't be just MAILBOXes */
	for (arg = args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GUID:
		case SEARCH_MAILBOX_GLOB:
			break;
		case SEARCH_OR:
			/* if each OR branch has something else than just
			   MAILBOXes, we're ok */
			if (expunge_search_args_is_msgset_or_ok(arg->value.subargs))
				return TRUE;
			break;
		case SEARCH_SUB:
			if (expunge_search_args_is_msgset_ok(arg->value.subargs))
				return TRUE;
			break;
		default:
			return TRUE;
		}
	}
	return FALSE;
}

static void
cmd_expunge_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	iter = doveadm_mail_list_iter_init(user, ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		(void)cmd_expunge_box(info, ctx->search_args);
	} T_END;
	doveadm_mail_list_iter_deinit(&iter);
}

void expunge_search_args_check(struct mail_search_args *args, const char *cmd)
{
	mail_search_args_simplify(args);
	if (!expunge_search_args_is_mailbox_ok(args->args)) {
		i_fatal("%s: To avoid accidents, search query "
			"must contain MAILBOX in all search branches", cmd);
	}
	if (!expunge_search_args_is_msgset_ok(args->args)) {
		i_fatal("%s: To avoid accidents, each branch in "
			"search query must contain something else "
			"besides MAILBOX", cmd);
	}
}

static void cmd_expunge_init(struct doveadm_mail_cmd_context *ctx,
			     const char *const args[])
{
	if (args[0] == NULL)
		doveadm_mail_help_name("expunge");

	ctx->search_args = doveadm_mail_build_search_args(args);
	expunge_search_args_check(ctx->search_args, "expunge");
}

static struct doveadm_mail_cmd_context *cmd_expunge_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_expunge_init;
	ctx->v.run = cmd_expunge_run;
	return ctx;
}

struct doveadm_mail_cmd cmd_expunge = {
	cmd_expunge_alloc, "expunge", "<search query>"
};
