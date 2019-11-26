/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "mail-storage.h"
#include "doveadm-mail.h"

struct save_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
};

static int
cmd_save_to_mailbox(struct save_cmd_context *ctx, struct mailbox *box,
		    struct istream *input)
{
	struct mail_storage *storage = mailbox_get_storage(box);
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	ssize_t ret;
	bool save_failed = FALSE;

	if (input->stream_errno != 0) {
		i_error("open(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		ctx->ctx.exit_code = EX_TEMPFAIL;
		return -1;
	}

	if (mailbox_open(box) < 0) {
		i_error("Failed to open mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_storage(&ctx->ctx, storage);
		return -1;
	}

	trans = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL |
					  ctx->ctx.transaction_flags, __func__);
	save_ctx = mailbox_save_alloc(trans);
	if (mailbox_save_begin(&save_ctx, input) < 0) {
		i_error("Saving failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_storage(&ctx->ctx, storage);
		mailbox_transaction_rollback(&trans);
		return -1;
	}
	do {
		if (mailbox_save_continue(save_ctx) < 0) {
			save_failed = TRUE;
			ret = -1;
			break;
		}
	} while ((ret = i_stream_read(input)) > 0);
	i_assert(ret == -1);

	if (input->stream_errno != 0) {
		i_error("read(msg input) failed: %s", i_stream_get_error(input));
		doveadm_mail_failed_error(&ctx->ctx, MAIL_ERROR_TEMP);
	} else if (save_failed) {
		i_error("Saving failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_storage(&ctx->ctx, storage);
	} else if (mailbox_save_finish(&save_ctx) < 0) {
		i_error("Saving failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_storage(&ctx->ctx, storage);
	} else if (mailbox_transaction_commit(&trans) < 0) {
		i_error("Save transaction commit failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_storage(&ctx->ctx, storage);
	} else {
		ret = 0;
	}
	if (save_ctx != NULL)
		mailbox_save_cancel(&save_ctx);
	if (trans != NULL)
		mailbox_transaction_rollback(&trans);
	i_assert(input->eof);
	return ret < 0 ? -1 : 0;
}

static int
cmd_save_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct save_cmd_context *ctx = (struct save_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	int ret;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	box = mailbox_alloc(ns->list, ctx->mailbox, MAILBOX_FLAG_SAVEONLY);
	mailbox_set_reason(box, _ctx->cmd->name);
	ret = cmd_save_to_mailbox(ctx, box, _ctx->cmd_input);
	mailbox_free(&box);
	return ret;
}

static void cmd_save_init(struct doveadm_mail_cmd_context *_ctx,
			  const char *const args[] ATTR_UNUSED)
{
	doveadm_mail_get_input(_ctx);
}

static bool
cmd_mailbox_save_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct save_cmd_context *ctx = (struct save_cmd_context *)_ctx;

	switch (c) {
	case 'm':
		ctx->mailbox = optarg;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_save_alloc(void)
{
	struct save_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct save_cmd_context);
	ctx->ctx.getopt_args = "m:";
	ctx->ctx.v.parse_arg = cmd_mailbox_save_parse_arg;
	ctx->ctx.v.init = cmd_save_init;
	ctx->ctx.v.run = cmd_save_run;
	ctx->mailbox = "INBOX";
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_save_ver2 = {
	.name = "save",
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-m mailbox]",
	.mail_cmd = cmd_save_alloc,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('m', "mailbox", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "file", CMD_PARAM_ISTREAM, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
