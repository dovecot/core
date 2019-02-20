/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "doveadm-print.h"
#include "doveadm-mailbox-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"
#include "mail-storage-private.h"

static int
cmd_rebuild_attachment_box(struct doveadm_mail_cmd_context *ctx,
			   const struct mailbox_info *info)
{
	struct doveadm_mail_iter *iter;
	struct mail *mail;
	int ret = 0;

	if (doveadm_mail_iter_init(ctx, info, ctx->search_args,
				   MAIL_FETCH_IMAP_BODYSTRUCTURE|
				   MAIL_FETCH_MESSAGE_PARTS, NULL, FALSE,
				   &iter) < 0)
		return -1;

	while (doveadm_mail_iter_next(iter, &mail) && ret >= 0) {
		T_BEGIN {
			doveadm_print(dec2str(mail->uid));
			switch(mail_set_attachment_keywords(mail)) {
			case -1:
				doveadm_print("error");
				doveadm_mail_failed_mailbox(ctx, mail->box);
				ret = -1;
				break;
			case 0:
				doveadm_print("no");
				break;
			case 1:
				doveadm_print("yes");
				break;
			default:
				i_unreached();
			}
		} T_END;
	}

	if (doveadm_mail_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static int
cmd_rebuild_attachment_run(struct doveadm_mail_cmd_context *ctx,
			   struct mail_user *user)
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
		if (cmd_rebuild_attachment_box(ctx, info) < 0)
			ret = -1;
	} T_END;
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static void cmd_rebuild_attachment_init(struct doveadm_mail_cmd_context *ctx,
					const char *const args[])
{
	doveadm_print_header_simple("uid");
	doveadm_print_header_simple("attachment");
	ctx->search_args = doveadm_mail_build_search_args(args);
}


static struct doveadm_mail_cmd_context *cmd_rebuild_attachment_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.init = cmd_rebuild_attachment_init;
	ctx->v.run = cmd_rebuild_attachment_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_rebuild_attachments = {
	.name = "rebuild attachments",
	.mail_cmd = cmd_rebuild_attachment_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<search query>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "query", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
