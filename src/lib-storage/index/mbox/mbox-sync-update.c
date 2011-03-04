/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "message-parser.h"
#include "index-storage.h"
#include "index-sync-changes.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"

/* Line length when to wrap X-IMAP, X-IMAPbase and X-Keywords headers to next
   line. Keep this pretty long, as after we wrap we lose compatibility with
   UW-IMAP */
#define KEYWORD_WRAP_LINE_LENGTH 1024

static void status_flags_append(struct mbox_sync_mail_context *ctx,
				const struct mbox_flag_type *flags_list)
{
	int i;

	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			str_append_c(ctx->header, flags_list[i].chr);
	}
}

void mbox_sync_move_buffer(struct mbox_sync_mail_context *ctx,
			   size_t pos, size_t need, size_t have)
{
	ssize_t diff = (ssize_t)need - (ssize_t)have;
	int i;

	i_assert(have < SSIZE_T_MAX);

	if (diff == 0) {
		if (ctx->header_last_change < pos + have ||
		    ctx->header_last_change == (size_t)-1)
			ctx->header_last_change = pos + have;
	} else {
		/* FIXME: if (diff < ctx->space && pos < ctx->offset) then
		   move the data only up to space offset and give/take the
		   space from there. update header_last_change accordingly.
		   (except pos and offset can't be compared directly) */
		ctx->header_last_change = (size_t)-1;
		for (i = 0; i < MBOX_HDR_COUNT; i++) {
			if (ctx->hdr_pos[i] > pos &&
			    ctx->hdr_pos[i] != (size_t)-1)
				ctx->hdr_pos[i] += diff;
		}

		if (ctx->mail.space > 0) {
			i_assert(ctx->mail.offset + ctx->mail.space <=
				 ctx->hdr_offset + pos ||
				 ctx->mail.offset > ctx->hdr_offset + pos + have);
			if (ctx->mail.offset > ctx->hdr_offset + pos) {
				/* free space offset moves */
				ctx->mail.offset += diff;
			}
		}

		if (diff < 0)
			str_delete(ctx->header, pos, -diff);
		else {
			ctx->header_last_change = (size_t)-1;
			buffer_copy(ctx->header, pos + diff,
				    ctx->header, pos, (size_t)-1);
		}
	}
}

static void status_flags_replace(struct mbox_sync_mail_context *ctx, size_t pos,
				 const struct mbox_flag_type *flags_list)
{
	unsigned char *data;
	size_t size;
	int i, need, have;

	ctx->mail.flags ^= MBOX_NONRECENT_KLUDGE;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;

	/* how many bytes do we need? */
	for (i = 0, need = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			need++;
	}

	/* how many bytes do we have now? */
	data = buffer_get_modifiable_data(ctx->header, &size);
	for (have = 0; pos < size; pos++) {
		if (data[pos] == '\n' || data[pos] == '\r')
			break;

		/* see if this is unknown flag for us */
		for (i = 0; flags_list[i].chr != 0; i++) {
			if (flags_list[i].chr == (char)data[pos])
				break;
		}

		if (flags_list[i].chr != 0)
			have++;
		else {
			/* save this one */
			data[pos-have] = data[pos];
		}
	}
	pos -= have;
        mbox_sync_move_buffer(ctx, pos, need, have);

	/* @UNSAFE */
	data = buffer_get_space_unsafe(ctx->header, pos, need);
	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			*data++ = flags_list[i].chr;
	}

	ctx->mail.flags ^= MBOX_NONRECENT_KLUDGE;
}

static void
keywords_append(struct mbox_sync_context *sync_ctx, string_t *dest,
		const ARRAY_TYPE(keyword_indexes) *keyword_indexes_arr)
{
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(&sync_ctx->mbox->box);
	const char *const *keyword_names;
	const unsigned int *keyword_indexes;
	unsigned int i, idx_count, keywords_count;
	size_t last_break;

	keyword_names = array_get(ibox->keyword_names,
				  &keywords_count);
	keyword_indexes = array_get(keyword_indexes_arr, &idx_count);

	for (i = 0, last_break = str_len(dest); i < idx_count; i++) {
		i_assert(keyword_indexes[i] < keywords_count);

		/* wrap the line whenever it gets too long */
		if (str_len(dest) - last_break < KEYWORD_WRAP_LINE_LENGTH) {
			if (i > 0)
				str_append_c(dest, ' ');
		} else {
			str_append(dest, "\n\t");
			last_break = str_len(dest);
		}
		str_append(dest, keyword_names[keyword_indexes[i]]);
	}
}

static void
keywords_append_all(struct mbox_sync_mail_context *ctx, string_t *dest,
		    size_t startpos)
{
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(&ctx->sync_ctx->mbox->box);
	const char *const *names;
	const unsigned char *p;
	unsigned int i, count;
	size_t last_break;

	p = str_data(dest);
	if (str_len(dest) - startpos < KEYWORD_WRAP_LINE_LENGTH)
		last_break = startpos;
	else {
		/* set last_break to beginning of line */
		for (last_break = str_len(dest); last_break > 0; last_break--) {
			if (p[last_break-1] == '\n')
				break;
		}
	}

	names = array_get(ibox->keyword_names, &count);
	for (i = 0; i < count; i++) {
		/* wrap the line whenever it gets too long */
		if (str_len(dest) - last_break < KEYWORD_WRAP_LINE_LENGTH)
			str_append_c(dest, ' ');
		else {
			str_append(dest, "\n\t");
			last_break = str_len(dest);
		}
		str_append(dest, names[i]);
	}
}

static void mbox_sync_add_missing_headers(struct mbox_sync_mail_context *ctx)
{
	size_t new_hdr_size, startpos;

	new_hdr_size = str_len(ctx->header);
	if (new_hdr_size > 0 &&
	    str_data(ctx->header)[new_hdr_size-1] != '\n') {
		/* broken header - doesn't end with \n. fix it. */
		str_append_c(ctx->header, '\n');
	}

	if (ctx->sync_ctx->dest_first_mail &&
	    ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] == (size_t)-1) {
		i_assert(ctx->sync_ctx->base_uid_validity != 0);

		str_append(ctx->header, "X-IMAPbase: ");
		ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] = str_len(ctx->header);
		/* startpos must start from identical position as when
		   updating */
		startpos = str_len(ctx->header);
		str_printfa(ctx->header, "%u ",
			    ctx->sync_ctx->base_uid_validity);

		ctx->last_uid_updated_value = ctx->sync_ctx->next_uid-1;
		ctx->last_uid_value_start_pos = str_len(ctx->header) -
			ctx->hdr_pos[MBOX_HDR_X_IMAPBASE];
		ctx->imapbase_updated = TRUE;
		str_printfa(ctx->header, "%010u", ctx->last_uid_updated_value);

		keywords_append_all(ctx, ctx->header, startpos);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->hdr_pos[MBOX_HDR_X_UID] == (size_t)-1 && !ctx->mail.pseudo) {
		str_append(ctx->header, "X-UID: ");
		ctx->hdr_pos[MBOX_HDR_X_UID] = str_len(ctx->header);
		str_printfa(ctx->header, "%u\n", ctx->mail.uid);
	}

	ctx->mail.flags ^= MBOX_NONRECENT_KLUDGE;

	if (ctx->hdr_pos[MBOX_HDR_STATUS] == (size_t)-1 &&
	    (ctx->mail.flags & STATUS_FLAGS_MASK) != 0) {
		str_append(ctx->header, "Status: ");
		ctx->hdr_pos[MBOX_HDR_STATUS] = str_len(ctx->header);
		status_flags_append(ctx, mbox_status_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->hdr_pos[MBOX_HDR_X_STATUS] == (size_t)-1 &&
	    (ctx->mail.flags & XSTATUS_FLAGS_MASK) != 0) {
		str_append(ctx->header, "X-Status: ");
		ctx->hdr_pos[MBOX_HDR_X_STATUS] = str_len(ctx->header);
		status_flags_append(ctx, mbox_xstatus_flags);
		str_append_c(ctx->header, '\n');
	}

	ctx->mail.flags ^= MBOX_NONRECENT_KLUDGE;

	if (ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] == (size_t)-1 &&
	    array_is_created(&ctx->mail.keywords) &&
	    array_count(&ctx->mail.keywords) > 0) {
		str_append(ctx->header, "X-Keywords: ");
		ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] = str_len(ctx->header);
		keywords_append(ctx->sync_ctx, ctx->header,
				&ctx->mail.keywords);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->content_length == (uoff_t)-1 &&
	    ctx->mail.body_size >= MBOX_MIN_CONTENT_LENGTH_SIZE) {
		str_printfa(ctx->header, "Content-Length: %"PRIuUOFF_T"\n",
			    ctx->mail.body_size);
	}

	if (str_len(ctx->header) != new_hdr_size) {
		if (ctx->header_first_change == (size_t)-1)
			ctx->header_first_change = new_hdr_size;
		ctx->header_last_change = (size_t)-1;
	}

	if (ctx->have_eoh)
		str_append_c(ctx->header, '\n');
}

static void mbox_sync_update_status(struct mbox_sync_mail_context *ctx)
{
	if (ctx->hdr_pos[MBOX_HDR_STATUS] != (size_t)-1) {
		status_flags_replace(ctx, ctx->hdr_pos[MBOX_HDR_STATUS],
				     mbox_status_flags);
	}
}

static void mbox_sync_update_xstatus(struct mbox_sync_mail_context *ctx)
{
	if (ctx->hdr_pos[MBOX_HDR_X_STATUS] != (size_t)-1) {
		status_flags_replace(ctx, ctx->hdr_pos[MBOX_HDR_X_STATUS],
				     mbox_xstatus_flags);
	}
}

static void mbox_sync_update_line(struct mbox_sync_mail_context *ctx,
				  size_t pos, string_t *new_line)
{
	const char *hdr, *p;
	uoff_t file_pos;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;

	/* set p = end of header, handle also wrapped headers */
	hdr = p = str_c(ctx->header) + pos;
	for (;;) {
		p = strchr(p, '\n');
		if (p == NULL) {
			/* shouldn't really happen, but allow anyway.. */
			p = hdr + strlen(hdr);
			break;
		}
		if (p[1] != '\t' && p[1] != ' ')
			break;
		p += 2;
	}

	file_pos = pos + ctx->hdr_offset;
	if (ctx->mail.space > 0 && ctx->mail.offset >= file_pos &&
	    ctx->mail.offset < file_pos + (p - hdr)) {
		/* extra space points to this line. remove it. */
		ctx->mail.offset = ctx->hdr_offset;
		ctx->mail.space = 0;
	}

	mbox_sync_move_buffer(ctx, pos, str_len(new_line), p - hdr + 1);
	buffer_copy(ctx->header, pos, new_line, 0, (size_t)-1);
}

static void mbox_sync_update_xkeywords(struct mbox_sync_mail_context *ctx)
{
	string_t *str;

	if (ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] == (size_t)-1)
		return;

	str = t_str_new(256);
	if (array_is_created(&ctx->mail.keywords))
		keywords_append(ctx->sync_ctx, str, &ctx->mail.keywords);
	str_append_c(str, '\n');
	mbox_sync_update_line(ctx, ctx->hdr_pos[MBOX_HDR_X_KEYWORDS], str);
}

static void mbox_sync_update_x_imap_base(struct mbox_sync_mail_context *ctx)
{
	struct mbox_sync_context *sync_ctx = ctx->sync_ctx;
	string_t *str;

	i_assert(sync_ctx->base_uid_validity != 0);

	if (!sync_ctx->dest_first_mail ||
	    ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] == (size_t)-1)
		return;

	if (!ctx->imapbase_rewrite) {
		/* uid-last might need updating, but we'll do it later by
		   writing it directly where needed. */
		return;
	}

	/* a) keyword list changed, b) uid-last didn't use 10 digits */
	str = t_str_new(200);
	str_printfa(str, "%u ", sync_ctx->base_uid_validity);

	ctx->last_uid_updated_value = sync_ctx->next_uid-1;
	ctx->last_uid_value_start_pos = str_len(str);
	ctx->imapbase_updated = TRUE;
	str_printfa(str, "%010u", ctx->last_uid_updated_value);

	keywords_append_all(ctx, str, 0);
	str_append_c(str, '\n');

        mbox_sync_update_line(ctx, ctx->hdr_pos[MBOX_HDR_X_IMAPBASE], str);
}

static void mbox_sync_update_x_uid(struct mbox_sync_mail_context *ctx)
{
	string_t *str;

	if (ctx->hdr_pos[MBOX_HDR_X_UID] == (size_t)-1 ||
	    ctx->mail.uid == ctx->parsed_uid)
		return;

	str = t_str_new(64);
	str_printfa(str, "%u\n", ctx->mail.uid);
	mbox_sync_update_line(ctx, ctx->hdr_pos[MBOX_HDR_X_UID], str);
}

static void mbox_sync_update_header_real(struct mbox_sync_mail_context *ctx)
{
	i_assert(ctx->mail.uid != 0 || ctx->mail.pseudo);

	if (!ctx->sync_ctx->keep_recent)
		ctx->mail.flags &= ~MAIL_RECENT;

	mbox_sync_update_status(ctx);
	mbox_sync_update_xstatus(ctx);
	mbox_sync_update_xkeywords(ctx);

	mbox_sync_update_x_imap_base(ctx);
	mbox_sync_update_x_uid(ctx);

	mbox_sync_add_missing_headers(ctx);
	ctx->updated = TRUE;
}

void mbox_sync_update_header(struct mbox_sync_mail_context *ctx)
{
	T_BEGIN {
		mbox_sync_update_header_real(ctx);
	} T_END;
}

static void
mbox_sync_update_header_from_real(struct mbox_sync_mail_context *ctx,
				  const struct mbox_sync_mail *mail)
{
	if ((ctx->mail.flags & STATUS_FLAGS_MASK) !=
	    (mail->flags & STATUS_FLAGS_MASK) ||
	    (ctx->mail.flags & MAIL_RECENT) != 0) {
		ctx->mail.flags = (ctx->mail.flags & ~STATUS_FLAGS_MASK) |
			(mail->flags & STATUS_FLAGS_MASK);
		if (!ctx->sync_ctx->keep_recent)
                        ctx->mail.flags &= ~MAIL_RECENT;
		mbox_sync_update_status(ctx);
	}
	if ((ctx->mail.flags & XSTATUS_FLAGS_MASK) !=
	    (mail->flags & XSTATUS_FLAGS_MASK)) {
		ctx->mail.flags = (ctx->mail.flags & ~XSTATUS_FLAGS_MASK) |
			(mail->flags & XSTATUS_FLAGS_MASK);
		mbox_sync_update_xstatus(ctx);
	}
	if (!array_is_created(&mail->keywords) ||
	    array_count(&mail->keywords) == 0) {
		/* no keywords for this mail */
		if (array_is_created(&ctx->mail.keywords)) {
			array_clear(&ctx->mail.keywords);
			mbox_sync_update_xkeywords(ctx);
		}
	} else if (!array_is_created(&ctx->mail.keywords)) {
		/* adding first keywords */
		p_array_init(&ctx->mail.keywords,
			     ctx->sync_ctx->mail_keyword_pool,
			     array_count(&mail->keywords));
		array_append_array(&ctx->mail.keywords,
				   &mail->keywords);
		mbox_sync_update_xkeywords(ctx);
	} else if (!array_cmp(&ctx->mail.keywords, &mail->keywords)) {
		/* keywords changed. */
		array_clear(&ctx->mail.keywords);
		array_append_array(&ctx->mail.keywords,
				   &mail->keywords);
		mbox_sync_update_xkeywords(ctx);
	}

	i_assert(ctx->mail.uid == 0 || ctx->mail.uid == mail->uid);
	ctx->mail.uid = mail->uid;

	mbox_sync_update_x_imap_base(ctx);
	mbox_sync_update_x_uid(ctx);
	mbox_sync_add_missing_headers(ctx);
}

void mbox_sync_update_header_from(struct mbox_sync_mail_context *ctx,
				  const struct mbox_sync_mail *mail)
{
	T_BEGIN {
		mbox_sync_update_header_from_real(ctx, mail);
	} T_END;
}
