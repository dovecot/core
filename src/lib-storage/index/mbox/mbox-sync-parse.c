/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "write-full.h"
#include "message-parser.h"
#include "mail-index.h"
#include "mbox-sync-private.h"

#include <stdlib.h>

#define IS_LWSP_LF(c) (IS_LWSP(c) || (c) == '\n')

struct mbox_flag_type mbox_status_flags[] = {
	{ 'R', MAIL_SEEN },
	{ 'O', MBOX_NONRECENT },
	{ 0, 0 }
};

struct mbox_flag_type mbox_xstatus_flags[] = {
	{ 'A', MAIL_ANSWERED },
	{ 'F', MAIL_FLAGGED },
	{ 'T', MAIL_DRAFT },
	{ 'D', MAIL_DELETED },
	{ 0, 0 }
};

struct header_func {
	const char *header;
	int (*func)(struct mbox_sync_mail_context *ctx,
		    struct message_header_line *hdr);
};

static enum mail_flags mbox_flag_find(struct mbox_flag_type *flags, char chr)
{
	int i;

	for (i = 0; flags[i].chr != 0; i++) {
		if (flags[i].chr == chr)
			return flags[i].flag;
	}

	return 0;
}

static void parse_status_flags(struct mbox_sync_mail_context *ctx,
			       struct message_header_line *hdr,
			       struct mbox_flag_type *flags_list)
{
	size_t i;

	for (i = 0; i < hdr->full_value_len; i++) {
		ctx->mail.flags |=
			mbox_flag_find(flags_list, hdr->full_value[i]);
	}
}

static int parse_status(struct mbox_sync_mail_context *ctx,
			struct message_header_line *hdr)
{
	parse_status_flags(ctx, hdr, mbox_status_flags);
	ctx->hdr_pos[MBOX_HDR_STATUS] = str_len(ctx->header);
	return TRUE;
}

static int parse_x_status(struct mbox_sync_mail_context *ctx,
			  struct message_header_line *hdr)
{
	parse_status_flags(ctx, hdr, mbox_xstatus_flags);
	ctx->hdr_pos[MBOX_HDR_X_STATUS] = str_len(ctx->header);
	return TRUE;
}

static int parse_x_imap_base(struct mbox_sync_mail_context *ctx,
			     struct message_header_line *hdr)
{
	const char *str;
	char *end;
	size_t pos;
	uint32_t uid_validity, uid_last;

	if (ctx->seq != 1 || ctx->seen_imapbase) {
		/* Valid only in first message */
		return FALSE;
	}

	/* <uid validity> <last uid> */
	t_push();
	str = t_strndup(hdr->full_value, hdr->full_value_len);
	uid_validity = strtoul(str, &end, 10);
	uid_last = strtoul(end, &end, 10);
	pos = end - str;
	t_pop();

	while (pos < hdr->full_value_len && IS_LWSP_LF(hdr->full_value[pos]))
		pos++;

	if (uid_validity == 0) {
		/* broken */
		return FALSE;
	}

	if (ctx->sync_ctx->base_uid_validity == 0) {
		ctx->sync_ctx->base_uid_validity = uid_validity;
		ctx->sync_ctx->base_uid_last = uid_last;
		ctx->sync_ctx->next_uid = uid_last+1;
	}

	ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] = str_len(ctx->header);
	ctx->seen_imapbase = TRUE;

	if (pos == hdr->full_value_len)
		return TRUE;

	// FIXME: save keywords

	return TRUE;
}

static int parse_x_keywords(struct mbox_sync_mail_context *ctx,
			    struct message_header_line *hdr)
{
	size_t i, space = 0;

	for (i = hdr->full_value_len; i > 0; i--) {
		if (!IS_LWSP_LF(hdr->full_value[i-1]))
			break;
		space++;
	}

	if (space > ctx->mail.space) {
		ctx->mail.offset = hdr->full_value_offset + i;
		ctx->mail.space = space;
	}

	// FIXME: parse them

	ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] = str_len(ctx->header);
	return TRUE;
}

static int parse_x_uid(struct mbox_sync_mail_context *ctx,
		       struct message_header_line *hdr)
{
	uint32_t value = 0;
	size_t i, space_pos, extra_space = 0;

	if (ctx->mail.uid != 0) {
		/* duplicate */
		return FALSE;
	}

	for (i = 0; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] < '0' || hdr->full_value[i] > '9')
			break;
		value = value*10 + (hdr->full_value[i] - '0');
	}

	space_pos = i;
	for (; i < hdr->full_value_len; i++) {
		if (!IS_LWSP_LF(hdr->full_value[i])) {
			/* broken value */
			return FALSE;
		}
		extra_space++;
	}

	if (value <= ctx->sync_ctx->prev_msg_uid) {
		/* broken - UIDs must be growing */
		return FALSE;
	}
	ctx->sync_ctx->prev_msg_uid = value;

	ctx->hdr_pos[MBOX_HDR_X_UID] = str_len(ctx->header);

	ctx->mail.uid = value;
	if (extra_space != 0 && ctx->mail.space == 0) {
		/* set it only if X-Keywords hasn't been seen. spaces in X-UID
		   should be removed when writing X-Keywords. */
		ctx->mail.offset = hdr->full_value_offset + space_pos;
		ctx->mail.space = extra_space;
	}
	return TRUE;
}

static int parse_content_length(struct mbox_sync_mail_context *ctx,
				struct message_header_line *hdr)
{
	uoff_t value = 0;
	size_t i;

	if (ctx->content_length != (uoff_t)-1) {
		/* duplicate */
		return FALSE;
	}

	for (i = 0; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] < '0' || hdr->full_value[i] > '9')
			break;
		value = value*10 + (hdr->full_value[i] - '0');
	}

	for (; i < hdr->full_value_len; i++) {
		if (!IS_LWSP_LF(hdr->full_value[i])) {
			/* broken value */
			return FALSE;
		}
	}

	ctx->content_length = value;
	return TRUE;
}

static struct header_func header_funcs[] = {
	{ "Content-Length", parse_content_length },
	{ "Status", parse_status },
	{ "X-IMAPbase", parse_x_imap_base },
	{ "X-Keywords", parse_x_keywords },
	{ "X-Status", parse_x_status },
	{ "X-UID", parse_x_uid },
	{ NULL, NULL }
};

static struct header_func *header_func_find(const char *header)
{
	int i;

	for (i = 0; header_funcs[i].header != NULL; i++) {
		if (strcasecmp(header_funcs[i].header, header) == 0)
			return &header_funcs[i];
	}
	return NULL;
}

void mbox_sync_parse_next_mail(struct istream *input,
			       struct mbox_sync_mail_context *ctx,
			       int rewriting)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	struct header_func *func;
	size_t line_start_pos;
	int i;

	ctx->hdr_offset = ctx->mail.offset;

        ctx->header_first_change = (size_t)-1;
	ctx->header_last_change = 0;

	for (i = 0; i < MBOX_HDR_COUNT; i++)
		ctx->hdr_pos[i] = (size_t)-1;

	ctx->content_length = (uoff_t)-1;
	str_truncate(ctx->header, 0);

        line_start_pos = 0;
	hdr_ctx = message_parse_header_init(input, NULL);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		if (hdr->eoh) {
			ctx->have_eoh = TRUE;
			break;
		}

		if (!hdr->continued) {
			line_start_pos = str_len(ctx->header);
			str_append(ctx->header, hdr->name);
			str_append(ctx->header, ": ");
		}

		func = header_func_find(hdr->name);
		if (func != NULL) {
			if (hdr->continues)
				hdr->use_full_value = TRUE;
			else if (!func->func(ctx, hdr)) {
				/* this header is broken, remove it */
				ctx->need_rewrite = TRUE;
				str_truncate(ctx->header, line_start_pos);
				if (ctx->header_first_change == (size_t)-1) {
					ctx->header_first_change =
						line_start_pos;
				}
				continue;
			}
			buffer_append(ctx->header, hdr->full_value,
				      hdr->full_value_len);
		} else {
			buffer_append(ctx->header, hdr->value,
				      hdr->value_len);
		}
		if (!hdr->no_newline)
			str_append_c(ctx->header, '\n');
	}
	message_parse_header_deinit(hdr_ctx);

	if (ctx->seq == 1 && ctx->sync_ctx->base_uid_validity == 0) {
		/* missing X-IMAPbase */
		ctx->need_rewrite = TRUE;
	}
	if (ctx->mail.uid == 0 && !rewriting) {
		/* missing X-UID */
		ctx->need_rewrite = TRUE;
		ctx->mail.uid = ctx->sync_ctx->next_uid++;
		ctx->sync_ctx->prev_msg_uid = ctx->mail.uid;
	}

	ctx->body_offset = input->v_offset;
}
