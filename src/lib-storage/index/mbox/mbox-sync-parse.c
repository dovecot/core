/* Copyright (C) 2004 Timo Sirainen */

/* MD5 header summing logic was pretty much copy&pasted from popa3d by
   Solar Designer */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "write-full.h"
#include "message-parser.h"
#include "mail-index.h"
#include "mbox-storage.h"
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

static void parse_trailing_whitespace(struct mbox_sync_mail_context *ctx,
				      struct message_header_line *hdr)
{
	size_t i, space = 0;

	/* the value may contain newlines. we can't count whitespace before
	   and after it as a single contiguous whitespace block, as that may
	   get us into situation where removing whitespace goes eg.
	   " \n \n" -> " \n\n" which would then be treated as end of headers.

	   that could probably be avoided by being careful, but as newlines
	   should never be there (we don't generate them), it's not worth the
	   trouble. */

	for (i = hdr->full_value_len; i > 0; i--) {
		if (!IS_LWSP(hdr->full_value[i-1]))
			break;
		space++;
	}

	if ((ssize_t)space > ctx->mail.space) {
		i_assert(space != 0);
		ctx->mail.offset = hdr->full_value_offset + i;
		ctx->mail.space = space;
	}
}

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
		if (ctx->sync_ctx->next_uid-1 <= uid_last)
			ctx->sync_ctx->next_uid = uid_last+1;
		else {
			ctx->sync_ctx->update_base_uid_last =
				ctx->sync_ctx->next_uid - 1;
			ctx->need_rewrite = TRUE;
		}
	}

	if (ctx->sync_ctx->next_uid <= ctx->sync_ctx->prev_msg_uid) {
		/* broken, update */
                ctx->sync_ctx->next_uid = ctx->sync_ctx->prev_msg_uid+1;
	}

	ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] = str_len(ctx->header);
	ctx->seen_imapbase = TRUE;

	if (pos == hdr->full_value_len)
		return TRUE;

	// FIXME: save keywords

        parse_trailing_whitespace(ctx, hdr);
	return TRUE;
}

static int parse_x_imap(struct mbox_sync_mail_context *ctx,
			struct message_header_line *hdr)
{
	if (!parse_x_imap_base(ctx, hdr))
		return FALSE;

	/* this is the c-client style "FOLDER INTERNAL DATA" message.
	   skip it. */
	ctx->pseudo = TRUE;
	return TRUE;
}

static int parse_x_keywords(struct mbox_sync_mail_context *ctx,
			    struct message_header_line *hdr)
{
	// FIXME: parse them

	ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] = str_len(ctx->header);
	parse_trailing_whitespace(ctx, hdr);
	return TRUE;
}

static int parse_x_uid(struct mbox_sync_mail_context *ctx,
		       struct message_header_line *hdr)
{
	uint32_t value = 0;
	size_t i;

	if (ctx->mail.uid != 0) {
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

	if (ctx->sync_ctx != NULL) {
		if (value >= ctx->sync_ctx->next_uid) {
			/* next_uid broken - fix it */
			ctx->sync_ctx->next_uid = value+1;
		}

		if (value <= ctx->sync_ctx->prev_msg_uid) {
			/* broken - UIDs must be growing */
			ctx->uid_broken = TRUE;
			return FALSE;
		}
		ctx->sync_ctx->prev_msg_uid = value;
	}

	ctx->mail.uid = value;

	if (ctx->sync_ctx == NULL) {
		/* we're in mbox_sync_parse_match_mail() */
		return TRUE;
	}

	if (ctx->sync_ctx->dest_first_mail && !ctx->seen_imapbase) {
		/* everything was good, except we can't have X-UID before
		   X-IMAPbase header (to keep c-client compatibility). keep
		   the UID, but when we're rewriting this makes sure the
		   X-UID is appended after X-IMAPbase. */
		return FALSE;
	}

	ctx->hdr_pos[MBOX_HDR_X_UID] = str_len(ctx->header);
	ctx->parsed_uid = value;
	parse_trailing_whitespace(ctx, hdr);
	return TRUE;
}

static int parse_x_uidl(struct mbox_sync_mail_context *ctx,
			struct message_header_line *hdr)
{
	size_t i;

	for (i = 0; i < hdr->full_value_len; i++) {
		if (IS_LWSP_LF(hdr->full_value[i]))
			break;
	}

	str_truncate(ctx->uidl, 0);
	str_append_n(ctx->uidl, hdr->full_value, i);
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

static int parse_date(struct mbox_sync_mail_context *ctx,
		      struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains date too, and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static int parse_delivered_to(struct mbox_sync_mail_context *ctx,
			      struct message_header_line *hdr)
{
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}

static int parse_message_id(struct mbox_sync_mail_context *ctx,
			    struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains unique ID too,
		   and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static int parse_received(struct mbox_sync_mail_context *ctx,
			  struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* get only the first received-header */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
		if (!hdr->continues)
			ctx->seen_received_hdr = TRUE;
	}
	return TRUE;
}

static int parse_x_delivery_id(struct mbox_sync_mail_context *ctx,
			       struct message_header_line *hdr)
{
	/* Let the local delivery agent help generate unique ID's but don't
	   blindly trust this header alone as it could just as easily come from
	   the remote. */
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}

static struct header_func header_funcs[] = {
	{ "Content-Length", parse_content_length },
	{ "Status", parse_status },
	{ "X-IMAP", parse_x_imap },
	{ "X-IMAPbase", parse_x_imap_base },
	{ "X-Keywords", parse_x_keywords },
	{ "X-Status", parse_x_status },
	{ "X-UID", parse_x_uid },
	{ "X-UIDL", parse_x_uidl }
};
#define HEADER_FUNCS_COUNT (sizeof(header_funcs) / sizeof(*header_funcs))

static struct header_func md5_header_funcs[] = {
	{ "Date", parse_date },
	{ "Delivered-To", parse_delivered_to },
	{ "Message-ID", parse_message_id },
	{ "Received", parse_received },
	{ "X-Delivery-ID", parse_x_delivery_id }
};
#define MD5_HEADER_FUNCS_COUNT \
	(sizeof(md5_header_funcs) / sizeof(*md5_header_funcs))

static int bsearch_header_func_cmp(const void *p1, const void *p2)
{
	const char *key = p1;
	const struct header_func *func = p2;

	return strcasecmp(key, func->header);
}

void mbox_sync_parse_next_mail(struct istream *input,
			       struct mbox_sync_mail_context *ctx)
{
	struct mbox_sync_context *sync_ctx = ctx->sync_ctx;
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	struct header_func *func;
	size_t line_start_pos;
	int i, ret;

	ctx->hdr_offset = ctx->mail.offset;

        ctx->header_first_change = (size_t)-1;
	ctx->header_last_change = 0;

	for (i = 0; i < MBOX_HDR_COUNT; i++)
		ctx->hdr_pos[i] = (size_t)-1;

	ctx->content_length = (uoff_t)-1;
	str_truncate(ctx->header, 0);

	md5_init(&ctx->hdr_md5_ctx);

        line_start_pos = 0;
	hdr_ctx = message_parse_header_init(input, NULL, FALSE);
	while ((ret = message_parse_header_next(hdr_ctx, &hdr)) > 0) {
		if (hdr->eoh) {
			ctx->have_eoh = TRUE;
			break;
		}

		if (!hdr->continued) {
			line_start_pos = str_len(ctx->header);
			str_append(ctx->header, hdr->name);
			str_append_n(ctx->header, hdr->middle, hdr->middle_len);
		}

		func = bsearch(hdr->name, md5_header_funcs,
			       MD5_HEADER_FUNCS_COUNT,
			       sizeof(*header_funcs), bsearch_header_func_cmp);
		if (func != NULL) {
			/* these functions do nothing more than update
			   MD5 sums */
			(void)func->func(ctx, hdr);
			func = NULL;
		} else {
			func = bsearch(hdr->name, header_funcs,
				       HEADER_FUNCS_COUNT,
				       sizeof(*header_funcs),
				       bsearch_header_func_cmp);
		}

		if (func != NULL) {
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				continue;
			}

			if (!func->func(ctx, hdr)) {
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
	i_assert(ret != 0);
	message_parse_header_deinit(hdr_ctx);

	md5_final(&ctx->hdr_md5_ctx, ctx->hdr_md5_sum);

	if ((ctx->seq == 1 && sync_ctx->base_uid_validity == 0) ||
	    (ctx->seq > 1 && sync_ctx->dest_first_mail)) {
		/* missing X-IMAPbase */
		ctx->need_rewrite = TRUE;
	}
	if (ctx->seq == 1 && sync_ctx->update_base_uid_last != 0 &&
	    sync_ctx->update_base_uid_last > sync_ctx->base_uid_last) {
		/* update uid-last field in X-IMAPbase */
		ctx->need_rewrite = TRUE;
	}

	ctx->body_offset = input->v_offset;
}

int mbox_sync_parse_match_mail(struct index_mailbox *ibox,
			       struct mail_index_view *view, uint32_t seq)
{
        struct mbox_sync_mail_context ctx;
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
	struct header_func *func;
	const void *data;
	uint32_t uid;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	md5_init(&ctx.hdr_md5_ctx);

	hdr_ctx = message_parse_header_init(ibox->mbox_stream, NULL, FALSE);
	while ((ret = message_parse_header_next(hdr_ctx, &hdr)) > 0) {
		if (hdr->eoh)
			break;

		func = bsearch(hdr->name, md5_header_funcs,
			       MD5_HEADER_FUNCS_COUNT,
			       sizeof(*header_funcs), bsearch_header_func_cmp);
		if (func != NULL) {
			/* these functions do nothing more than update
			   MD5 sums */
			(void)func->func(&ctx, hdr);
		} else if (strcasecmp(hdr->name, "X-UID") == 0) {
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				continue;
			}
			(void)parse_x_uid(&ctx, hdr);

			if (ctx.mail.uid != 0)
				break;
		}
	}
	i_assert(ret != 0);
	message_parse_header_deinit(hdr_ctx);

	md5_final(&ctx.hdr_md5_ctx, ctx.hdr_md5_sum);

	if (ctx.mail.uid != 0) {
		/* match by X-UID header */
		if (mail_index_lookup_uid(view, seq, &uid) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}
		return ctx.mail.uid == uid;
	}

	/* match by MD5 sum */
	if (ibox->md5hdr_ext_idx == 0) {
		ibox->md5hdr_ext_idx =
			mail_index_ext_register(ibox->index, "header-md5",
						0, 16, 1);
	}

	if (mail_index_lookup_ext(view, seq, ibox->md5hdr_ext_idx, &data) < 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}
	return data == NULL ? 0 :
		memcmp(data, ctx.hdr_md5_sum, 16) == 0;
}
