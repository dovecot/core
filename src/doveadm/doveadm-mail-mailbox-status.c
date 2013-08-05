/* Copyright (c) 2010-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"

#define ALL_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_RECENT | \
	 STATUS_UIDNEXT | STATUS_UIDVALIDITY | \
	 STATUS_UNSEEN | STATUS_HIGHESTMODSEQ)
#define ALL_METADATA_ITEMS \
	(MAILBOX_METADATA_VIRTUAL_SIZE | MAILBOX_METADATA_GUID)

#define TOTAL_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_RECENT | STATUS_UNSEEN)
#define TOTAL_METADATA_ITEMS \
	(MAILBOX_METADATA_VIRTUAL_SIZE)

struct status_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	struct mail_search_args *search_args;

	enum mailbox_status_items status_items;
	enum mailbox_metadata_items metadata_items;
	struct mailbox_status total_status;
	struct mailbox_metadata total_metadata;

	unsigned int total_sum:1;
};

static void status_parse_fields(struct status_cmd_context *ctx,
				const char *const *fields)
{
	if (*fields == NULL)
		i_fatal_status(EX_USAGE, "No status fields");

	for (; *fields != NULL; fields++) {
		const char *field = *fields;

		if (strcmp(field, "all") == 0) {
			if (ctx->total_sum) {
				ctx->status_items |= TOTAL_STATUS_ITEMS;
				ctx->metadata_items |= TOTAL_METADATA_ITEMS;
			} else {
				ctx->status_items |= ALL_STATUS_ITEMS;
				ctx->metadata_items |= ALL_METADATA_ITEMS;
			}
		} else if (strcmp(field, "messages") == 0)
			ctx->status_items |= STATUS_MESSAGES;
		else if (strcmp(field, "recent") == 0)
			ctx->status_items |= STATUS_RECENT;
		else if (strcmp(field, "uidnext") == 0)
			ctx->status_items |= STATUS_UIDNEXT;
		else if (strcmp(field, "uidvalidity") == 0)
			ctx->status_items |= STATUS_UIDVALIDITY;
		else if (strcmp(field, "unseen") == 0)
			ctx->status_items |= STATUS_UNSEEN;
		else if (strcmp(field, "highestmodseq") == 0)
			ctx->status_items |= STATUS_HIGHESTMODSEQ;
		else if (strcmp(field, "vsize") == 0)
			ctx->metadata_items |= MAILBOX_METADATA_VIRTUAL_SIZE;
		else if (strcmp(field, "guid") == 0)
			ctx->metadata_items |= MAILBOX_METADATA_GUID;
		else {
			i_fatal_status(EX_USAGE,
				       "Unknown status field: %s", field);
		}

		if (ctx->total_sum &&
		    ((ctx->status_items & ~TOTAL_STATUS_ITEMS) != 0 ||
		     (ctx->metadata_items & ~TOTAL_METADATA_ITEMS) != 0)) {
			i_fatal_status(EX_USAGE,
				"Status field %s can't be used with -t", field);
		}
	}
}

static void ATTR_NULL(2)
status_output(struct status_cmd_context *ctx, struct mailbox *box,
	      const struct mailbox_status *status,
	      const struct mailbox_metadata *metadata)
{
	if (box != NULL)
		doveadm_print(mailbox_get_vname(box));

	if ((ctx->status_items & STATUS_MESSAGES) != 0)
		doveadm_print_num(status->messages);
	if ((ctx->status_items & STATUS_RECENT) != 0)
		doveadm_print_num(status->recent);
	if ((ctx->status_items & STATUS_UIDNEXT) != 0)
		doveadm_print_num(status->uidnext);
	if ((ctx->status_items & STATUS_UIDVALIDITY) != 0)
		doveadm_print_num(status->uidvalidity);
	if ((ctx->status_items & STATUS_UNSEEN) != 0)
		doveadm_print_num(status->unseen);
	if ((ctx->status_items & STATUS_HIGHESTMODSEQ) != 0)
		doveadm_print_num(status->highest_modseq);
	if ((ctx->metadata_items & MAILBOX_METADATA_VIRTUAL_SIZE) != 0)
		doveadm_print_num(metadata->virtual_size);
	if ((ctx->metadata_items & MAILBOX_METADATA_GUID) != 0)
		doveadm_print(guid_128_to_string(metadata->guid));
}

static void
status_sum(struct status_cmd_context *ctx,
	   const struct mailbox_status *status,
	   const struct mailbox_metadata *metadata)
{
	struct mailbox_status *dest = &ctx->total_status;

	dest->messages += status->messages;
	dest->recent += status->recent;
	dest->unseen += status->unseen;
	ctx->total_metadata.virtual_size += metadata->virtual_size;
}

static int
status_mailbox(struct status_cmd_context *ctx, const struct mailbox_info *info)
{
	struct mailbox *box;
	struct mailbox_status status;
	struct mailbox_metadata metadata;

	box = doveadm_mailbox_find(ctx->ctx.cur_mail_user, info->vname);
	if (mailbox_get_status(box, ctx->status_items, &status) < 0 ||
	    mailbox_get_metadata(box, ctx->metadata_items, &metadata) < 0) {
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		mailbox_free(&box);
		return -1;
	}
	if (!ctx->total_sum)
		status_output(ctx, box, &status, &metadata);
	else
		status_sum(ctx, &status, &metadata);
	mailbox_free(&box);
	return 0;
}

static int
cmd_mailbox_status_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;
	enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mailbox_list_iter *iter;
	const struct mailbox_info *info;
	int ret = 0;

	memset(&ctx->total_status, 0, sizeof(ctx->total_status));
	memset(&ctx->total_metadata, 0, sizeof(ctx->total_metadata));

	iter = doveadm_mailbox_list_iter_init(_ctx, user, ctx->search_args,
					      iter_flags);
	while ((info = doveadm_mailbox_list_iter_next(iter)) != NULL) {
		T_BEGIN {
			if (status_mailbox(ctx, info) < 0)
				ret = -1;
		} T_END;
	}
	if (doveadm_mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;

	if (ctx->total_sum) {
		status_output(ctx, NULL, &ctx->total_status,
			      &ctx->total_metadata);
	}
	return ret;
}

static void cmd_mailbox_status_init(struct doveadm_mail_cmd_context *_ctx,
				    const char *const args[])
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;
	const char *fields = args[0];

	if (fields == NULL || args[1] == NULL)
		doveadm_mail_help_name("mailbox status");

	status_parse_fields(ctx, t_strsplit_spaces(fields, " "));
	ctx->search_args = doveadm_mail_mailbox_search_args_build(args+1);

	if (!ctx->total_sum) {
		doveadm_print_header("mailbox", "mailbox",
				     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	}
	if ((ctx->status_items & STATUS_MESSAGES) != 0)
		doveadm_print_header_simple("messages");
	if ((ctx->status_items & STATUS_RECENT) != 0)
		doveadm_print_header_simple("recent");
	if ((ctx->status_items & STATUS_UIDNEXT) != 0)
		doveadm_print_header_simple("uidnext");
	if ((ctx->status_items & STATUS_UIDVALIDITY) != 0)
		doveadm_print_header_simple("uidvalidity");
	if ((ctx->status_items & STATUS_UNSEEN) != 0)
		doveadm_print_header_simple("unseen");
	if ((ctx->status_items & STATUS_HIGHESTMODSEQ) != 0)
		doveadm_print_header_simple("highestmodseq");
	if ((ctx->metadata_items & MAILBOX_METADATA_VIRTUAL_SIZE) != 0)
		doveadm_print_header_simple("vsize");
	if ((ctx->metadata_items & MAILBOX_METADATA_GUID) != 0)
		doveadm_print_header_simple("guid");
}

static void cmd_mailbox_status_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;

	mail_search_args_unref(&ctx->search_args);
}

static bool
cmd_mailbox_status_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;

	switch (c) {
	case 't':
		ctx->total_sum = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_mailbox_status_alloc(void)
{
	struct status_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct status_cmd_context);
	ctx->ctx.getopt_args = "t";
	ctx->ctx.v.parse_arg = cmd_mailbox_status_parse_arg;
	ctx->ctx.v.init = cmd_mailbox_status_init;
	ctx->ctx.v.deinit = cmd_mailbox_status_deinit;
	ctx->ctx.v.run = cmd_mailbox_status_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_mailbox_status = {
	cmd_mailbox_status_alloc, "mailbox status",
	"[-t] <fields> <mailbox mask> [...]"
};
