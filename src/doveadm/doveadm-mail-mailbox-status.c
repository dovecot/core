/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "doveadm-mail.h"
#include "doveadm-mail-list-iter.h"

#define TOTAL_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_RECENT | STATUS_UNSEEN | STATUS_VIRTUAL_SIZE)

struct status_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	struct mail_search_args *search_args;
	enum mailbox_status_items items;
	struct mailbox_status total_status;

	unsigned int guid:1;
	unsigned int total_sum:1;
};

static void status_parse_fields(struct status_cmd_context *ctx,
				const char *const *fields)
{
	if (*fields == NULL)
		i_fatal("No status fields");

	for (; *fields != NULL; fields++) {
		const char *field = *fields;

		if (strcmp(field, "messages") == 0)
			ctx->items |= STATUS_MESSAGES;
		else if (strcmp(field, "recent") == 0)
			ctx->items |= STATUS_RECENT;
		else if (strcmp(field, "uidnext") == 0)
			ctx->items |= STATUS_UIDNEXT;
		else if (strcmp(field, "uidvalidity") == 0)
			ctx->items |= STATUS_UIDVALIDITY;
		else if (strcmp(field, "unseen") == 0)
			ctx->items |= STATUS_UNSEEN;
		else if (strcmp(field, "highestmodseq") == 0)
			ctx->items |= STATUS_HIGHESTMODSEQ;
		else if (strcmp(field, "vsize") == 0)
			ctx->items |= STATUS_VIRTUAL_SIZE;
		else if (strcmp(field, "guid") == 0)
			ctx->guid = TRUE;
		else
			i_fatal("Unknown status field: %s", field);

		if (ctx->total_sum &&
		    ((ctx->items & ~TOTAL_STATUS_ITEMS) != 0 || ctx->guid))
			i_fatal("Status field %s can't be used with -t", field);
	}
}

static void status_output(struct status_cmd_context *ctx, struct mailbox *box,
			  const struct mailbox_status *status,
			  uint8_t mailbox_guid[MAIL_GUID_128_SIZE])
{
	string_t *str = t_str_new(128);

	if (box != NULL)
		str_printfa(str, "%s: ", mailbox_get_vname(box));

	if ((ctx->items & STATUS_MESSAGES) != 0)
		str_printfa(str, "messages=%u ", status->messages);
	if ((ctx->items & STATUS_RECENT) != 0)
		str_printfa(str, "recent=%u ", status->recent);
	if ((ctx->items & STATUS_UIDNEXT) != 0)
		str_printfa(str, "uidnext=%u ", status->uidnext);
	if ((ctx->items & STATUS_UIDVALIDITY) != 0)
		str_printfa(str, "uidvalidity=%u ", status->uidvalidity);
	if ((ctx->items & STATUS_UNSEEN) != 0)
		str_printfa(str, "unseen=%u ", status->unseen);
	if ((ctx->items & STATUS_HIGHESTMODSEQ) != 0) {
		str_printfa(str, "highestmodseq=%llu ",
			    (unsigned long long)status->highest_modseq);
	}
	if ((ctx->items & STATUS_VIRTUAL_SIZE) != 0) {
		str_printfa(str, "vsize=%llu ",
			    (unsigned long long)status->virtual_size);
	}
	if (ctx->guid) {
		str_printfa(str, "guid=%s ",
			    mail_guid_128_to_string(mailbox_guid));
	}

	str_truncate(str, str_len(str)-1);
	dm_printf(&ctx->ctx, "%s\n", str_c(str));
}

static void
status_sum(struct status_cmd_context *ctx,
	   const struct mailbox_status *status)
{
	struct mailbox_status *dest = &ctx->total_status;

	dest->messages += status->messages;
	dest->recent += status->recent;
	dest->unseen += status->unseen;
	dest->virtual_size += status->virtual_size;
}

static void
status_mailbox(struct status_cmd_context *ctx, const struct mailbox_info *info)
{
	struct mailbox *box;
	struct mailbox_status status;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];

	box = doveadm_mailbox_find_and_sync(ctx->ctx.cur_mail_user, info->name);
	mailbox_get_status(box, ctx->items, &status);
	if (ctx->guid) {
		if (mailbox_get_guid(box, mailbox_guid) < 0)
			memset(mailbox_guid, 0, sizeof(mailbox_guid));
	}
	if (!ctx->total_sum)
		status_output(ctx, box, &status, mailbox_guid);
	else
		status_sum(ctx, &status);
	mailbox_free(&box);
}

static void
cmd_mailbox_status_run(struct doveadm_mail_cmd_context *_ctx,
		       struct mail_user *user)
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;
	enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	memset(&ctx->total_status, 0, sizeof(ctx->total_status));

	iter = doveadm_mail_list_iter_init(user, ctx->search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) {
		T_BEGIN {
			status_mailbox(ctx, info);
		} T_END;
	}
	doveadm_mail_list_iter_deinit(&iter);

	if (ctx->total_sum)
		status_output(ctx, NULL, &ctx->total_status, NULL);
}

static void cmd_mailbox_status_init(struct doveadm_mail_cmd_context *_ctx,
				    const char *const args[])
{
	struct status_cmd_context *ctx = (struct status_cmd_context *)_ctx;
	const char *fields = args[0];

	if (fields == NULL || args[1] == NULL)
		doveadm_mail_help_name("mailbox status");

	status_parse_fields(ctx, t_strsplit_spaces(fields, " "));
	ctx->search_args = doveadm_mail_mailbox_search_args_build(args);
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
	ctx->ctx.v.run = cmd_mailbox_status_run;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_mailbox_status = {
	cmd_mailbox_status_alloc, "mailbox status",
	"[-t] <fields> <mailbox mask> [...]"
};
