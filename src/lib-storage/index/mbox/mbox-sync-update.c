#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "message-parser.h"
#include "mbox-sync-private.h"

static void status_flags_append(struct mbox_sync_mail_context *ctx,
				const struct mbox_flag_type *flags_list)
{
	int i;

	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			str_append_c(ctx->header, flags_list[i].chr);
	}
}

static void status_flags_replace(struct mbox_sync_mail_context *ctx, size_t pos,
				const struct mbox_flag_type *flags_list)
{
	unsigned char *data;
	size_t size;
	int i, need, have;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;

	/* how many bytes do we need? */
	for (i = 0, need = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			need++;
	}

	/* how many bytes do we have now? */
	data = buffer_get_modifyable_data(ctx->header, &size);
	for (have = 0; pos < size; pos++) {
		if (data[pos] == '\n')
			break;

		/* see if this is unknown flag for us */
		for (i = 0; flags_list[i].chr != 0; i++) {
			if (flags_list[i].chr == data[pos])
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

	if (need < have)
		str_delete(ctx->header, pos, have-need);
	else if (need > have) {
		buffer_copy(ctx->header, pos + (need-have),
			    ctx->header, pos, (size_t)-1);
	}

	for (i = 0; i < MBOX_HDR_COUNT; i++) {
		if (ctx->hdr_pos[i] > pos &&
		    ctx->hdr_pos[i] != (size_t)-1)
			ctx->hdr_pos[i] += need - have;
	}

	/* @UNSAFE */
	data = buffer_get_space_unsafe(ctx->header, pos, need);
	for (i = 0, need = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail.flags & flags_list[i].flag) != 0)
			*data++ = flags_list[i].chr;
	}
}

static void keywords_append(struct mbox_sync_mail_context *ctx,
			    keywords_mask_t keywords)
{
	// FIXME
}

static void mbox_sync_add_missing_headers(struct mbox_sync_mail_context *ctx)
{
	size_t old_hdr_size, new_hdr_size;
	int i, have_keywords;

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header);

	if (ctx->seq == 1 && ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] == (size_t)-1) {
		ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] = str_len(ctx->header);
		str_printfa(ctx->header, "X-IMAPbase: %u %u",
			    ctx->sync_ctx->base_uid_validity,
			    ctx->sync_ctx->next_uid-1);
		//FIXME:keywords_append(ctx, all_keywords);
		str_append_c(ctx->header, '\n');
	}
	i_assert(ctx->sync_ctx->base_uid_validity != 0);

	if (ctx->hdr_pos[MBOX_HDR_X_UID] == (size_t)-1) {
		ctx->hdr_pos[MBOX_HDR_X_UID] = str_len(ctx->header);
		str_printfa(ctx->header, "X-UID: %u\n", ctx->mail.uid);
	}

	if (ctx->hdr_pos[MBOX_HDR_STATUS] == (size_t)-1 &&
	    (ctx->mail.flags & STATUS_FLAGS_MASK) != 0) {
		ctx->mail.flags |= MBOX_NONRECENT;
		ctx->hdr_pos[MBOX_HDR_STATUS] = str_len(ctx->header);
		str_append(ctx->header, "Status: ");
		status_flags_append(ctx, mbox_status_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->hdr_pos[MBOX_HDR_X_STATUS] == (size_t)-1 &&
	    (ctx->mail.flags & XSTATUS_FLAGS_MASK) != 0) {
		ctx->hdr_pos[MBOX_HDR_X_STATUS] = str_len(ctx->header);
		str_append(ctx->header, "X-Status: ");
		status_flags_append(ctx, mbox_xstatus_flags);
		str_append_c(ctx->header, '\n');
	}

	have_keywords = FALSE;
	for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++) {
		if (ctx->mail.keywords[i] != 0) {
			have_keywords = TRUE;
			break;
		}
	}

	if (ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] == (size_t)-1 && have_keywords) {
		ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] = str_len(ctx->header);
		str_append(ctx->header, "X-Keywords: ");
		keywords_append(ctx, ctx->mail.keywords);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->content_length == (uoff_t)-1) {
		str_printfa(ctx->header, "Content-Length: %"PRIuUOFF_T"\n",
			    ctx->mail.body_size);
	}

	if (str_len(ctx->header) != new_hdr_size) {
		if (ctx->header_first_change == (size_t)-1)
			ctx->header_first_change = new_hdr_size;
		ctx->header_last_change = (size_t)-1;
		ctx->mail.space -= str_len(ctx->header) - new_hdr_size;
		if (ctx->mail.space > 0) {
			/* we should rewrite this header, so offset
			   must be broken if it's used anymore. */
			ctx->mail.offset = (uoff_t)-1;
		} else {
			/* we don't have enough space for this header, change
			   offset to point back to beginning of headers */
			ctx->mail.offset = ctx->hdr_offset;
		}
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

static void mbox_sync_update_xkeywords(struct mbox_sync_mail_context *ctx)
{
	// FIXME
}

void mbox_sync_update_header(struct mbox_sync_mail_context *ctx,
			     buffer_t *syncs_buf)
{
	const struct mail_index_sync_rec *sync;
	size_t size, i;
	uint8_t old_flags;
	keywords_mask_t old_keywords;

	sync = buffer_get_data(syncs_buf, &size);
	size /= sizeof(*sync);

	if (size != 0) {
		old_flags = ctx->mail.flags;
		memcpy(old_keywords, ctx->mail.keywords, sizeof(old_keywords));

		for (i = 0; i < size; i++) {
			mail_index_sync_flags_apply(&sync[i], &ctx->mail.flags,
						    ctx->mail.keywords);
		}

		if ((old_flags & STATUS_FLAGS_MASK) !=
		    (ctx->mail.flags & STATUS_FLAGS_MASK))
			mbox_sync_update_status(ctx);
		if ((old_flags & XSTATUS_FLAGS_MASK) !=
		    (ctx->mail.flags & XSTATUS_FLAGS_MASK))
			mbox_sync_update_xstatus(ctx);
		if (memcmp(old_keywords, ctx->mail.keywords,
			   INDEX_KEYWORDS_BYTE_COUNT) != 0)
			mbox_sync_update_xkeywords(ctx);
	} else {
		if ((ctx->mail.flags & MBOX_NONRECENT) == 0) {
			ctx->mail.flags |= MBOX_NONRECENT;
			mbox_sync_update_status(ctx);
		}
	}

        mbox_sync_add_missing_headers(ctx);
}

void mbox_sync_update_header_from(struct mbox_sync_mail_context *ctx,
				  const struct mbox_sync_mail *mail)
{
	if ((ctx->mail.flags & STATUS_FLAGS_MASK) !=
	    (mail->flags & STATUS_FLAGS_MASK) ||
	    (ctx->mail.flags & MBOX_NONRECENT) == 0) {
		ctx->mail.flags = (ctx->mail.flags & ~STATUS_FLAGS_MASK) |
			(mail->flags & STATUS_FLAGS_MASK) | MBOX_NONRECENT;
		mbox_sync_update_status(ctx);
	}
	if ((ctx->mail.flags & XSTATUS_FLAGS_MASK) !=
	    (mail->flags & XSTATUS_FLAGS_MASK)) {
		ctx->mail.flags = (ctx->mail.flags & ~XSTATUS_FLAGS_MASK) |
			(mail->flags & XSTATUS_FLAGS_MASK);
		mbox_sync_update_xstatus(ctx);
	}
	if (memcmp(ctx->mail.keywords, mail->keywords,
		   INDEX_KEYWORDS_BYTE_COUNT) != 0) {
		memcpy(ctx->mail.keywords, mail->keywords,
		       INDEX_KEYWORDS_BYTE_COUNT);
		mbox_sync_update_xkeywords(ctx);
	}

	i_assert(ctx->mail.uid == 0 || ctx->mail.uid == mail->uid);
	ctx->mail.uid = mail->uid;
	mbox_sync_add_missing_headers(ctx);
}
