#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "message-parser.h"
#include "mbox-sync-private.h"

static void status_flags_append(struct mbox_sync_mail_context *ctx,
				struct mbox_flag_type *flags_list)
{
	int i;

	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail->flags & flags_list[i].flag) != 0)
			str_append_c(ctx->header, flags_list[i].chr);
	}
}
static void keywords_append(struct mbox_sync_mail_context *ctx,
			    custom_flags_mask_t custom_flags)
{
	// FIXME
}

static void mbox_sync_add_missing_headers(struct mbox_sync_mail_context *ctx)
{
	size_t old_hdr_size, new_hdr_size;
	int i, have_keywords;

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header) + ctx->have_eoh;

	if (ctx->seq == 1 && ctx->base_uid_validity == 0) {
		ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] = str_len(ctx->header);
		str_printfa(ctx->header, "X-IMAPbase: %u %u",
			    ctx->sync_ctx->hdr->uid_validity,
			    ctx->sync_ctx->next_uid);
		//FIXME:keywords_append(ctx, all_custom_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->mail->uid == 0) {
		ctx->hdr_pos[MBOX_HDR_X_UID] = str_len(ctx->header);
		str_printfa(ctx->header, "X-UID: %u\n",
			    ctx->sync_ctx->next_uid++);
	}

	if (ctx->hdr_pos[MBOX_HDR_STATUS] == (size_t)-1 &&
	    (ctx->mail->flags & STATUS_FLAGS_MASK) != 0) {
		ctx->hdr_pos[MBOX_HDR_STATUS] = str_len(ctx->header);
		str_append(ctx->header, "Status: ");
		status_flags_append(ctx, mbox_status_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->hdr_pos[MBOX_HDR_X_STATUS] == (size_t)-1 &&
	    (ctx->mail->flags & XSTATUS_FLAGS_MASK) != 0) {
		ctx->hdr_pos[MBOX_HDR_X_STATUS] = str_len(ctx->header);
		str_append(ctx->header, "X-Status: ");
		status_flags_append(ctx, mbox_xstatus_flags);
		str_append_c(ctx->header, '\n');
	}

	have_keywords = FALSE;
	for (i = 0; i < INDEX_CUSTOM_FLAGS_BYTE_COUNT; i++) {
		if (ctx->mail->custom_flags[i] != 0) {
			have_keywords = TRUE;
			break;
		}
	}

	if (ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] == (size_t)-1 && have_keywords) {
		ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] = str_len(ctx->header);
		str_append(ctx->header, "X-Keywords: ");
		keywords_append(ctx, ctx->mail->custom_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->content_length == (uoff_t)-1) {
		str_printfa(ctx->header, "Content-Length: %"PRIuUOFF_T"\n",
			    ctx->mail->body_size);
	}

	if (str_len(ctx->header) != new_hdr_size) {
		if (ctx->header_first_change == (size_t)-1)
			ctx->header_first_change = new_hdr_size;
		ctx->header_last_change = (size_t)-1;
		ctx->mail->space -= str_len(ctx->header) -
			(new_hdr_size - ctx->have_eoh);
		new_hdr_size = str_len(ctx->header) + ctx->have_eoh;
	}

	if (ctx->header_first_change == (size_t)-1) {
		/* no headers had to be modified */
		return;
	}

	if (ctx->have_eoh)
		str_append_c(ctx->header, '\n');
}

static void mbox_sync_update_status(struct mbox_sync_mail_context *ctx)
{
}

static void mbox_sync_update_xstatus(struct mbox_sync_mail_context *ctx)
{
}

static void mbox_sync_update_xkeywords(struct mbox_sync_mail_context *ctx)
{
}

void mbox_sync_update_header(struct mbox_sync_mail_context *ctx,
			     struct mail_index_sync_rec *update)
{
	uint8_t old_flags;
	custom_flags_mask_t old_custom_flags;

	if (update != NULL) {
		old_flags = ctx->mail->flags;
		memcpy(old_custom_flags, ctx->mail->custom_flags,
		       sizeof(old_custom_flags));

		mail_index_sync_flags_apply(update, &ctx->mail->flags,
					    ctx->mail->custom_flags);

		if ((old_flags & STATUS_FLAGS_MASK) !=
		    (ctx->mail->flags & STATUS_FLAGS_MASK))
			mbox_sync_update_status(ctx);
		if ((old_flags & XSTATUS_FLAGS_MASK) !=
		    (ctx->mail->flags & XSTATUS_FLAGS_MASK))
			mbox_sync_update_xstatus(ctx);
		if (memcmp(old_custom_flags, ctx->mail->custom_flags,
			   sizeof(old_custom_flags)) != 0)
			mbox_sync_update_xkeywords(ctx);
	}

        mbox_sync_add_missing_headers(ctx);
}
