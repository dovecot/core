/* Copyright (C) 2004 Timo Sirainen */

/*
   Modifying mbox can be slow, so we try to do it all at once minimizing the
   required disk I/O. We may need to:

   - Update message flags in Status, X-Status and X-Keywords headers
   - Write missing X-UID and X-IMAPbase headers
   - Write missing or broken Content-Length header if there's space
   - Expunge specified messages

   Here's how we do it:

   - Start reading the mails from the beginning
   - X-Keywords, X-UID and X-IMAPbase headers may contain padding at the end
     of them, remember how much each message has and offset to beginning of the
     padding
   - If header needs to be rewritten and there's enough space, do it
       - If we didn't have enough space, remember how much was missing
   - Continue reading and counting the padding in each message. If available
     padding is enough to rewrite all the previous messages needing it, do it
   - When we encounter expunged message, treat all of it as padding and
     rewrite previous messages if needed (and there's enough space).
     Afterwards keep moving messages backwards to fill the expunged space.
     Moving is done by rewriting each message's headers, with possibly adding
     missing Content-Length header and padding. Message bodies are moved
     without modifications.
   - If we encounter end of file, grow the file and rewrite needed messages
   - Rewriting is done by moving message body forward, rewriting message's
     header and doing the same for previous message, until all of them are
     rewritten.
*/

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "istream.h"
#include "file-set-size.h"
#include "str.h"
#include "write-full.h"
#include "istream-raw-mbox.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-lock.h"
#include "mbox-sync-private.h"

#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>

#define MBOX_SYNC_SECS 1

int mbox_sync_seek(struct mbox_sync_context *sync_ctx, uoff_t from_offset)
{
	if (istream_raw_mbox_seek(sync_ctx->input, from_offset) < 0) {
		mail_storage_set_critical(sync_ctx->ibox->box.storage,
			"Unexpectedly lost From-line at offset %"PRIuUOFF_T
			" from mbox file %s", from_offset,
			sync_ctx->ibox->path);
		return -1;
	}
	return 0;
}

static int mbox_sync_grow_file(struct mbox_sync_context *sync_ctx,
			       struct mbox_sync_mail_context *mail_ctx,
			       uoff_t grow_size)
{
	uoff_t src_offset, file_size;

	i_assert(grow_size > 0);

	/* put the padding between last message's header and body */
	file_size = i_stream_get_size(sync_ctx->file_input) + grow_size;
	if (file_set_size(sync_ctx->fd, file_size) < 0) {
		mbox_set_syscall_error(sync_ctx->ibox, "file_set_size()");
		return -1;
	}

	src_offset = mail_ctx->body_offset;
	mail_ctx->body_offset += grow_size;
	if (mbox_move(sync_ctx, mail_ctx->body_offset, src_offset,
		      file_size - mail_ctx->body_offset) < 0)
		return -1;

	istream_raw_mbox_flush(sync_ctx->input);
	return 0;
}

static void mbox_sync_buffer_delete_old(buffer_t *syncs_buf, uint32_t uid)
{
	struct mail_index_sync_rec *sync;
	size_t size, src, dest;

	sync = buffer_get_modifyable_data(syncs_buf, &size);
	size /= sizeof(*sync);

	for (src = dest = 0; src < size; src++) {
		if (sync[src].uid2 > uid) {
			if (src != dest)
				sync[dest] = sync[src];
			dest++;
		}
	}

	buffer_set_used_size(syncs_buf, dest * sizeof(*sync));
}

static int
mbox_sync_read_next_mail(struct mbox_sync_context *sync_ctx,
			 struct mbox_sync_mail_context *mail_ctx)
{
	/* get EOF */
	(void)istream_raw_mbox_get_header_offset(sync_ctx->input);
	if (istream_raw_mbox_is_eof(sync_ctx->input))
		return 0;

	memset(mail_ctx, 0, sizeof(*mail_ctx));
	mail_ctx->sync_ctx = sync_ctx;
	mail_ctx->seq = ++sync_ctx->seq;
	mail_ctx->header = sync_ctx->header;
	mail_ctx->uidl = sync_ctx->uidl;
	str_truncate(mail_ctx->uidl, 0);

	mail_ctx->mail.from_offset =
		istream_raw_mbox_get_start_offset(sync_ctx->input);
	mail_ctx->mail.offset =
		istream_raw_mbox_get_header_offset(sync_ctx->input);

	if (mail_ctx->seq == 1)
		sync_ctx->seen_first_mail = TRUE;
	if (mail_ctx->seq > 1 && sync_ctx->dest_first_mail) {
		/* First message was expunged and this is the next one.
		   Skip \n header */
		mail_ctx->mail.from_offset++;
	}

	mbox_sync_parse_next_mail(sync_ctx->input, mail_ctx);
	i_assert(sync_ctx->input->v_offset != mail_ctx->mail.from_offset ||
		 sync_ctx->input->eof);

	mail_ctx->mail.body_size =
		istream_raw_mbox_get_body_size(sync_ctx->input,
					       mail_ctx->content_length);
	i_assert(mail_ctx->mail.body_size < OFF_T_MAX);

	if ((mail_ctx->mail.flags & MBOX_NONRECENT) == 0 && !mail_ctx->pseudo) {
		if (!sync_ctx->ibox->keep_recent) {
			/* need to add 'O' flag to Status-header */
			mail_ctx->need_rewrite = TRUE;
		}
		mail_ctx->recent = TRUE;
	}
	return 1;
}

static int mbox_sync_buf_have_expunges(buffer_t *syncs_buf)
{
	const struct mail_index_sync_rec *sync;
	size_t size, i;

	sync = buffer_get_data(syncs_buf, &size);
	size /= sizeof(*sync);

	for (i = 0; i < size; i++) {
		if (sync[i].type == MAIL_INDEX_SYNC_TYPE_EXPUNGE)
			return TRUE;
	}
	return FALSE;
}

static int mbox_sync_read_index_syncs(struct mbox_sync_context *sync_ctx,
				      uint32_t uid, int *sync_expunge_r)
{
	struct mail_index_sync_rec *sync_rec = &sync_ctx->sync_rec;
	int ret;

	*sync_expunge_r = FALSE;

	if (sync_ctx->index_sync_ctx == NULL)
		return 0;

	if (uid == 0) {
		/* nothing for this or the future ones */
		uid = (uint32_t)-1;
	}

	mbox_sync_buffer_delete_old(sync_ctx->syncs, uid);
	while (uid >= sync_rec->uid1) {
		if (uid <= sync_rec->uid2 &&
		    sync_rec->type != MAIL_INDEX_SYNC_TYPE_APPEND &&
		    (sync_rec->type != MAIL_INDEX_SYNC_TYPE_EXPUNGE ||
		     !sync_ctx->ibox->mbox_readonly)) {
			buffer_append(sync_ctx->syncs, sync_rec,
				      sizeof(*sync_rec));

			if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE)
				*sync_expunge_r = TRUE;
		}

		ret = mail_index_sync_next(sync_ctx->index_sync_ctx, sync_rec);
		if (ret < 0) {
			mail_storage_set_index_error(sync_ctx->ibox);
			return -1;
		}

		if (ret == 0) {
			memset(sync_rec, 0, sizeof(*sync_rec));
			break;
		}

		if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_APPEND) {
			if (sync_rec->uid2 >= sync_ctx->next_uid) {
				sync_ctx->next_uid = sync_rec->uid2 + 1;
                                sync_ctx->update_base_uid_last = sync_rec->uid2;
			}
			memset(sync_rec, 0, sizeof(*sync_rec));
		}
	}

	if (!*sync_expunge_r)
		*sync_expunge_r = mbox_sync_buf_have_expunges(sync_ctx->syncs);

	return 0;
}

static void mbox_sync_apply_index_syncs(buffer_t *syncs_buf, uint8_t *flags,
					keywords_mask_t keywords)
{
	const struct mail_index_sync_rec *sync;
	size_t size, i;

	sync = buffer_get_data(syncs_buf, &size);
	size /= sizeof(*sync);

	for (i = 0; i < size; i++) {
		if (sync[i].type != MAIL_INDEX_SYNC_TYPE_FLAGS)
			continue;
		mail_index_sync_flags_apply(&sync[i], flags, keywords);
	}
}

static int
mbox_sync_read_index_rec(struct mbox_sync_context *sync_ctx,
			 uint32_t uid, const struct mail_index_record **rec_r)
{
        const struct mail_index_record *rec = NULL;
	uint32_t messages_count;
	int ret = 0;

	messages_count = mail_index_view_get_message_count(sync_ctx->sync_view);
	while (sync_ctx->idx_seq <= messages_count) {
		ret = mail_index_lookup(sync_ctx->sync_view,
					sync_ctx->idx_seq, &rec);
		if (ret < 0) {
			mail_storage_set_index_error(sync_ctx->ibox);
			return -1;
		}

		if (uid <= rec->uid)
			break;

		/* externally expunged message, remove from index */
		mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq);
                sync_ctx->idx_seq++;
		rec = NULL;
	}

	if (ret == 0 && uid < sync_ctx->hdr->next_uid) {
		/* this UID was already in index and it was expunged */
		mail_storage_set_critical(sync_ctx->ibox->box.storage,
			"mbox sync: Expunged message reappeared in mailbox %s "
			"(UID %u < %u)", sync_ctx->ibox->path, uid,
			sync_ctx->hdr->next_uid);
		ret = 0;
	} else if (rec != NULL && rec->uid != uid) {
		/* new UID in the middle of the mailbox - shouldn't happen */
		mail_storage_set_critical(sync_ctx->ibox->box.storage,
			"mbox sync: UID inserted in the middle of mailbox %s "
			"(%u > %u)", sync_ctx->ibox->path, rec->uid, uid);
		ret = 0; rec = NULL;
	} else {
		ret = 1;
	}

	*rec_r = rec;
	return ret;
}

static int mbox_sync_find_index_md5(struct mbox_sync_context *sync_ctx,
				    unsigned char hdr_md5_sum[],
				    const struct mail_index_record **rec_r)
{
        const struct mail_index_record *rec = NULL;
	uint32_t messages_count;
	const void *data;
	int ret;

	messages_count = mail_index_view_get_message_count(sync_ctx->sync_view);
	while (sync_ctx->idx_seq <= messages_count) {
		ret = mail_index_lookup(sync_ctx->sync_view,
					sync_ctx->idx_seq, &rec);
		if (ret < 0) {
			mail_storage_set_index_error(sync_ctx->ibox);
			return -1;
		}

		if (mail_index_lookup_extra(sync_ctx->sync_view,
					    sync_ctx->idx_seq,
					    sync_ctx->ibox->md5hdr_extra_idx,
					    &data) < 0) {
			mail_storage_set_index_error(sync_ctx->ibox);
			return -1;
		}

		if (data != NULL && memcmp(data, hdr_md5_sum, 16) == 0)
			break;

		/* externally expunged message, remove from index */
		mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq);
                sync_ctx->idx_seq++;
		rec = NULL;
	}

	*rec_r = rec;
	return 0;
}

static int
mbox_sync_update_from_offset(struct mbox_sync_context *sync_ctx,
                             struct mbox_sync_mail *mail,
			     int nocheck)
{
	const void *data;
	uint64_t offset;

	if (!nocheck) {
		/* see if from_offset needs updating */
		if (mail_index_lookup_extra(sync_ctx->sync_view,
					    sync_ctx->idx_seq,
					    sync_ctx->ibox->mbox_extra_idx,
					    &data) < 0) {
			mail_storage_set_index_error(sync_ctx->ibox);
			return -1;
		}

		if (data != NULL &&
		    *((const uint64_t *)data) == mail->from_offset)
			return 0;
	}

	offset = mail->from_offset;
	mail_index_update_extra_rec(sync_ctx->t, sync_ctx->idx_seq,
				    sync_ctx->ibox->mbox_extra_idx, &offset);
	return 0;
}

static int mbox_sync_update_index(struct mbox_sync_context *sync_ctx,
                                  struct mbox_sync_mail_context *mail_ctx,
				  const struct mail_index_record *rec)
{
	struct mbox_sync_mail *mail = &mail_ctx->mail;
	keywords_mask_t idx_keywords;
	uint8_t idx_flags, mbox_flags;

	if (rec == NULL) {
		/* new message */
		mail_index_append(sync_ctx->t, mail->uid, &sync_ctx->idx_seq);
		mbox_flags = mail->flags & (MAIL_FLAGS_MASK^MAIL_RECENT);
		if (mail_ctx->dirty)
			mbox_flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
		if (sync_ctx->ibox->keep_recent &&
		    (mail->flags & MBOX_NONRECENT) == 0)
			mbox_flags |= MAIL_RECENT;
		mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
					MODIFY_REPLACE, mbox_flags,
					mail->keywords);

		if (sync_ctx->ibox->md5hdr_extra_idx != 0) {
			mail_index_update_extra_rec(sync_ctx->t,
				sync_ctx->idx_seq,
				sync_ctx->ibox->md5hdr_extra_idx,
				mail_ctx->hdr_md5_sum);
		}

		if (str_len(mail_ctx->uidl) > 0) {
			/*FIXME:mail_cache_add(sync_ctx->cache_trans,
				       MAIL_CACHE_UID_STRING,
				       str_data(mail_ctx->uidl),
				       str_len(mail_ctx->uidl));*/
		}
	} else {
		/* see if flags changed */
		idx_flags = rec->flags;
		memcpy(idx_keywords, rec->keywords, INDEX_KEYWORDS_BYTE_COUNT);
		mbox_sync_apply_index_syncs(sync_ctx->syncs,
					    &idx_flags, idx_keywords);

		if ((idx_flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* flags are dirty, ignore whatever was in the file */
			mbox_flags = idx_flags;
		} else {
			mbox_flags = (rec->flags & ~MAIL_FLAGS_MASK) |
				(mail->flags & MAIL_FLAGS_MASK);
			mbox_flags ^= MAIL_RECENT;
		}

		if (mail_ctx->dirty)
			mbox_flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
		else if (!sync_ctx->delay_writes)
			mbox_flags &= ~MAIL_INDEX_MAIL_FLAG_DIRTY;

		if ((idx_flags & ~MAIL_INDEX_MAIL_FLAG_DIRTY) ==
		    (mbox_flags & ~MAIL_INDEX_MAIL_FLAG_DIRTY) &&
		    memcmp(idx_keywords, mail->keywords,
			   INDEX_KEYWORDS_BYTE_COUNT) == 0) {
			if (idx_flags != mbox_flags) {
				/* dirty flag state changed */
				int dirty = (mbox_flags &
					     MAIL_INDEX_MAIL_FLAG_DIRTY) != 0;
				memset(idx_keywords, 0,
				       INDEX_KEYWORDS_BYTE_COUNT);
				mail_index_update_flags(sync_ctx->t,
					sync_ctx->idx_seq,
					dirty ? MODIFY_ADD : MODIFY_REMOVE,
					MAIL_INDEX_MAIL_FLAG_DIRTY,
					idx_keywords);
			}
		} else if ((idx_flags & ~MAIL_RECENT) !=
			   (mbox_flags & ~MAIL_RECENT) ||
			   memcmp(idx_keywords, mail->keywords,
				  INDEX_KEYWORDS_BYTE_COUNT) != 0) {
			mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
						MODIFY_REPLACE, mbox_flags,
						mail->keywords);
		} else if (((idx_flags ^ mbox_flags) & MAIL_RECENT) != 0) {
			/* drop recent flag */
			memset(idx_keywords, 0, INDEX_KEYWORDS_BYTE_COUNT);
			mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
						MODIFY_REMOVE, MAIL_RECENT,
						idx_keywords);
		}
	}

	if (mail_ctx->recent)
		index_mailbox_set_recent(sync_ctx->ibox, sync_ctx->idx_seq);

	/* update from_offsets, but not if we're going to rewrite this message.
	   rewriting would just move it anyway. */
	if (sync_ctx->need_space_seq == 0) {
		int nocheck = rec == NULL || sync_ctx->expunged_space > 0;
		if (mbox_sync_update_from_offset(sync_ctx, mail, nocheck) < 0)
			return -1;
	}
	return 0;
}

static int mbox_read_from_line(struct mbox_sync_mail_context *ctx)
{
	struct istream *input = ctx->sync_ctx->file_input;
	const unsigned char *data;
	size_t size, from_line_size;

	buffer_set_used_size(ctx->sync_ctx->from_line, 0);
	from_line_size = ctx->hdr_offset - ctx->mail.from_offset;

	i_stream_seek(input, ctx->mail.from_offset);
	for (;;) {
		data = i_stream_get_data(input, &size);
		if (size >= from_line_size)
			size = from_line_size;

		buffer_append(ctx->sync_ctx->from_line, data, size);
		i_stream_skip(input, size);
		from_line_size -= size;

		if (from_line_size == 0)
			break;

		if (i_stream_read(input) < 0)
			return -1;
	}

	return 0;
}

static int
mbox_write_from_line(struct mbox_sync_mail_context *ctx)
{
	string_t *str = ctx->sync_ctx->from_line;

	if (pwrite_full(ctx->sync_ctx->fd, str_data(str), str_len(str),
			ctx->mail.from_offset) < 0) {
		mbox_set_syscall_error(ctx->sync_ctx->ibox, "pwrite_full()");
		return -1;
	}

	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 0;
}

static void update_from_offsets(struct mbox_sync_context *sync_ctx)
{
	const struct mbox_sync_mail *mails;
	uint32_t idx, extra_idx;
	uint64_t offset;
	size_t size;

	extra_idx = sync_ctx->ibox->mbox_extra_idx;

	mails = buffer_get_modifyable_data(sync_ctx->mails, &size);
	size /= sizeof(*mails);

	for (idx = 0; idx < size; idx++) {
		if (mails[idx].idx_seq == 0 ||
		    (mails[idx].flags & MBOX_EXPUNGED) != 0)
			continue;

		offset = mails[idx].from_offset;
		mail_index_update_extra_rec(sync_ctx->t, mails[idx].idx_seq,
					    extra_idx, &offset);
	}
}

static void mbox_sync_handle_expunge(struct mbox_sync_mail_context *mail_ctx)
{
	mail_ctx->mail.flags = MBOX_EXPUNGED;
	mail_ctx->mail.offset = mail_ctx->mail.from_offset;
	mail_ctx->mail.space =
		mail_ctx->body_offset - mail_ctx->mail.from_offset +
		mail_ctx->mail.body_size;
	mail_ctx->mail.body_size = 0;

	if (mail_ctx->sync_ctx->dest_first_mail) {
		/* expunging first message, fix space to contain next
		   message's \n header too since it will be removed. */
		mail_ctx->mail.space++;
	}

	mail_ctx->sync_ctx->expunged_space += mail_ctx->mail.space;
}

static int mbox_sync_handle_header(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	off_t move_diff;
	int ret;

	if (sync_ctx->expunged_space > 0 && sync_ctx->need_space_seq == 0) {
		/* move the header backwards to fill expunged space */
		move_diff = -sync_ctx->expunged_space;

		/* read the From-line before rewriting overwrites it */
		if (mbox_read_from_line(mail_ctx) < 0)
			return -1;

		mbox_sync_update_header(mail_ctx, sync_ctx->syncs);
		ret = mbox_sync_try_rewrite(mail_ctx, move_diff, FALSE);
		if (ret < 0)
			return -1;

		if (ret > 0) {
			/* rewrite successful, write From-line to
			   new location */
			mail_ctx->mail.from_offset += move_diff;
			mail_ctx->mail.offset += move_diff;
			if (mbox_write_from_line(mail_ctx) < 0)
				return -1;
		}
	} else if (mail_ctx->need_rewrite ||
		   buffer_get_used_size(sync_ctx->syncs) != 0 ||
		   (mail_ctx->seq == 1 &&
		    sync_ctx->update_base_uid_last != 0)) {
		mbox_sync_update_header(mail_ctx, sync_ctx->syncs);
		if (sync_ctx->delay_writes) {
			/* mark it dirty and do it later */
			mail_ctx->dirty = TRUE;
			return 0;
		}

		if ((ret = mbox_sync_try_rewrite(mail_ctx, 0, FALSE)) < 0)
			return -1;
	} else {
		/* nothing to do */
		return 0;
	}

	if (ret == 0 && sync_ctx->need_space_seq == 0) {
		/* first mail with no space to write it */
		sync_ctx->need_space_seq = sync_ctx->seq;
		sync_ctx->space_diff = 0;

		if (sync_ctx->expunged_space > 0) {
			/* create dummy message to describe the expunged data */
			struct mbox_sync_mail mail;

			memset(&mail, 0, sizeof(mail));
			mail.flags = MBOX_EXPUNGED;
			mail.offset = mail_ctx->mail.from_offset -
				sync_ctx->expunged_space;
			mail.space = sync_ctx->expunged_space;

			sync_ctx->need_space_seq--;
			buffer_append(sync_ctx->mails, &mail, sizeof(mail));
		}
	}
	return 0;
}

static int
mbox_sync_handle_missing_space(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	uoff_t padding;
	uint32_t last_seq;

	buffer_append(sync_ctx->mails, &mail_ctx->mail, sizeof(mail_ctx->mail));

	sync_ctx->space_diff += mail_ctx->mail.space;
	if (sync_ctx->space_diff < 0)
		return 0;

	/* we have enough space now */
	padding = MBOX_HEADER_PADDING *
		(sync_ctx->seq - sync_ctx->need_space_seq + 1);

	if (mail_ctx->mail.uid == 0 &&
	    (uoff_t)sync_ctx->space_diff > padding) {
		/* don't waste too much on padding */
		sync_ctx->expunged_space = sync_ctx->space_diff - padding;
		sync_ctx->space_diff = padding;
		last_seq = sync_ctx->seq - 1;
		buffer_set_used_size(sync_ctx->mails, sync_ctx->mails->used -
				     sizeof(mail_ctx->mail));
	} else {
		sync_ctx->expunged_space = 0;
		last_seq = sync_ctx->seq;
	}

	if (mbox_sync_rewrite(sync_ctx, sync_ctx->space_diff,
			      sync_ctx->need_space_seq, last_seq) < 0)
		return -1;

	update_from_offsets(sync_ctx);

	/* mail_ctx may contain wrong data after rewrite, so make sure we
	   don't try to access it */
	memset(mail_ctx, 0, sizeof(*mail_ctx));

	sync_ctx->need_space_seq = 0;
	buffer_set_used_size(sync_ctx->mails, 0);
	return 0;
}

static int
mbox_sync_seek_to_seq(struct mbox_sync_context *sync_ctx, uint32_t seq)
{
	struct index_mailbox *ibox = sync_ctx->ibox;
	uoff_t old_offset;
	uint32_t uid;
	int ret, deleted;

	if (seq == 0) {
		if (istream_raw_mbox_seek(ibox->mbox_stream, 0) < 0) {
			mail_storage_set_error(ibox->box.storage,
				"Mailbox isn't a valid mbox file");
			return -1;
		}
		seq++;
	} else {
		old_offset = istream_raw_mbox_get_start_offset(sync_ctx->input);

		ret = mbox_file_seek(ibox, sync_ctx->sync_view, seq, &deleted);
		if (ret < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		if (ret == 0) {
			if (istream_raw_mbox_seek(ibox->mbox_stream,
						  old_offset) < 0) {
				mail_storage_set_critical(ibox->box.storage,
					"Error seeking back to original "
					"offset %s in mbox file %s",
					dec2str(old_offset), ibox->path);
				return -1;
			}
			return 0;
		}
	}

	if (seq <= 1)
		uid = 0;
	else if (mail_index_lookup_uid(sync_ctx->sync_view, seq-1, &uid) < 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}

	sync_ctx->prev_msg_uid = uid;

        /* set to -1, since it's always increased later */
	sync_ctx->seq = seq-1;
	if (sync_ctx->seq == 0 &&
	    istream_raw_mbox_get_start_offset(sync_ctx->input) != 0) {
		/* this mbox has pseudo mail which contains the X-IMAP header */
		sync_ctx->seq++;
	}

        sync_ctx->idx_seq = seq;
	sync_ctx->dest_first_mail = sync_ctx->seq == 0;
        (void)istream_raw_mbox_get_body_offset(sync_ctx->input);
	return 1;
}

static int
mbox_sync_seek_to_uid(struct mbox_sync_context *sync_ctx, uint32_t uid)
{
	uint32_t seq1, seq2;

	if (mail_index_lookup_uid_range(sync_ctx->sync_view, uid, (uint32_t)-1,
					&seq1, &seq2) < 0) {
		mail_storage_set_index_error(sync_ctx->ibox);
		return -1;
	}

	return mbox_sync_seek_to_seq(sync_ctx, seq1);
}

static int mbox_sync_loop(struct mbox_sync_context *sync_ctx,
			  struct mbox_sync_mail_context *mail_ctx,
			  uint32_t min_message_count, int partial)
{
	const struct mail_index_record *rec;
	uint32_t uid, messages_count;
	uoff_t offset;
	int ret, expunged;

	messages_count = mail_index_view_get_message_count(sync_ctx->sync_view);

	if (!mail_index_sync_have_more(sync_ctx->index_sync_ctx) ||
	    (!partial && min_message_count != 0)) {
		ret = mbox_sync_seek_to_seq(sync_ctx, partial ?
					    messages_count : 0);
	} else {
		/* we sync only what we need to. jump to first record that
		   needs updating */
		const struct mail_index_sync_rec *sync_rec;
		size_t size;

		if (buffer_get_used_size(sync_ctx->syncs) == 0 &&
		    sync_ctx->sync_rec.uid1 == 0) {
			if (mbox_sync_read_index_syncs(sync_ctx, 1,
						       &expunged) < 0)
				return -1;

			if (buffer_get_used_size(sync_ctx->syncs) == 0 &&
			    sync_ctx->sync_rec.uid1 == 0) {
				/* nothing to do */
				return 1;
			}
		}

		sync_rec = buffer_get_data(sync_ctx->syncs, &size);
		if (size == 0)
			sync_rec = &sync_ctx->sync_rec;

		ret = mbox_sync_seek_to_uid(sync_ctx, sync_rec->uid1);
	}

	if (ret <= 0)
		return ret;

	while ((ret = mbox_sync_read_next_mail(sync_ctx, mail_ctx)) > 0) {
		uid = mail_ctx->mail.uid;

		if (mail_ctx->seq == 1 && sync_ctx->base_uid_validity != 0 &&
                    sync_ctx->hdr->uid_validity != 0 &&
		    sync_ctx->base_uid_validity !=
		    sync_ctx->hdr->uid_validity) {
			mail_storage_set_critical(sync_ctx->ibox->box.storage,
				"UIDVALIDITY changed (%u -> %u) "
				"in mbox file %s",
				sync_ctx->hdr->uid_validity,
				sync_ctx->base_uid_validity,
				sync_ctx->ibox->path);
                        mail_index_mark_corrupted(sync_ctx->ibox->index);
			return -1;
		}

		if (mail_ctx->uid_broken && partial) {
			/* UID ordering problems, resync everything to make
			   sure we get everything right */
			return 0;
		}

		if (mail_ctx->pseudo)
			uid = 0;

		rec = NULL;
		if (uid != 0) {
			ret = mbox_sync_read_index_rec(sync_ctx, uid, &rec);
			if (ret < 0)
				return -1;
			if (ret == 0)
				uid = 0;
		}

		if (uid == 0 && !mail_ctx->pseudo &&
		    (sync_ctx->delay_writes ||
		     sync_ctx->idx_seq <= messages_count)) {
			/* If we can't use/store X-UID header, use MD5 sum.
			   Also check for existing MD5 sums when we're actually
			   able to write X-UIDs. */
			if (sync_ctx->ibox->md5hdr_extra_idx == 0) {
				sync_ctx->ibox->md5hdr_extra_idx =
					mail_index_register_record_extra(
						sync_ctx->ibox->index,
						"header-md5", 0, 16);
			}

			if (mbox_sync_find_index_md5(sync_ctx,
						     mail_ctx->hdr_md5_sum,
						     &rec) < 0)
				return -1;

			if (rec != NULL)
				uid = mail_ctx->mail.uid = rec->uid;
		}

		if (!mail_ctx->pseudo) {
			/* get all sync records related to this message */
			if (mbox_sync_read_index_syncs(sync_ctx, uid,
						       &expunged) < 0)
				return -1;
		} else {
			expunged = FALSE;
		}

		if (uid == 0 && !mail_ctx->pseudo) {
			/* missing/broken X-UID. all the rest of the mails
			   need new UIDs. */
			while (sync_ctx->idx_seq <= messages_count) {
				mail_index_expunge(sync_ctx->t,
						   sync_ctx->idx_seq++);
			}
			mail_ctx->need_rewrite = TRUE;
			mail_ctx->mail.uid = sync_ctx->next_uid++;
			sync_ctx->prev_msg_uid = mail_ctx->mail.uid;
		}

		mail_ctx->mail.idx_seq = sync_ctx->idx_seq;

		if (!expunged) {
			if (mbox_sync_handle_header(mail_ctx) < 0)
				return -1;
			sync_ctx->dest_first_mail = FALSE;
		} else {
			mail_ctx->mail.uid = 0;
			mbox_sync_handle_expunge(mail_ctx);
		}

		if (!mail_ctx->pseudo) {
			if (!expunged) {
				if (mbox_sync_update_index(sync_ctx, mail_ctx,
							   rec) < 0)
					return -1;
			}
			sync_ctx->idx_seq++;
		}

		istream_raw_mbox_next(sync_ctx->input,
				      mail_ctx->mail.body_size);
		offset = istream_raw_mbox_get_start_offset(sync_ctx->input);

		if (sync_ctx->need_space_seq != 0) {
			if (mbox_sync_handle_missing_space(mail_ctx) < 0)
				return -1;
			if (mbox_sync_seek(sync_ctx, offset) < 0)
				return -1;
		} else if (sync_ctx->expunged_space > 0) {
			if (!expunged) {
				/* move the body */
				if (mbox_move(sync_ctx,
					      mail_ctx->body_offset -
					      sync_ctx->expunged_space,
					      mail_ctx->body_offset,
					      mail_ctx->mail.body_size) < 0)
					return -1;
				if (mbox_sync_seek(sync_ctx, offset) < 0)
					return -1;
			}
		} else if (sync_ctx->seq >= min_message_count) {
			mbox_sync_buffer_delete_old(sync_ctx->syncs, uid);
			if (buffer_get_used_size(sync_ctx->syncs) == 0) {
				/* if there's no sync records left,
				   we can stop */
				if (sync_ctx->sync_rec.uid1 == 0)
					break;

				/* we can skip forward to next record which
				   needs updating. if it failes because the
				   offset is dirty, just ignore and continue
				   from where we are now. */
				uid = sync_ctx->sync_rec.uid1;
				if (mbox_sync_seek_to_uid(sync_ctx, uid) < 0)
					return -1;
			}
		}
	}

	if (istream_raw_mbox_is_eof(sync_ctx->input)) {
		/* rest of the messages in index don't exist -> expunge them */
		while (sync_ctx->idx_seq <= messages_count)
			mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq++);
	}

	if (!partial)
		sync_ctx->ibox->mbox_sync_dirty = FALSE;

	return 1;
}

static int mbox_sync_handle_eof_updates(struct mbox_sync_context *sync_ctx,
					struct mbox_sync_mail_context *mail_ctx)
{
	uoff_t offset, padding, trailer_size;
	int need_rewrite;

	if (!istream_raw_mbox_is_eof(sync_ctx->input)) {
		i_assert(sync_ctx->need_space_seq == 0);
		i_assert(sync_ctx->expunged_space == 0);
		return 0;
	}

	trailer_size = i_stream_get_size(sync_ctx->file_input) -
		sync_ctx->file_input->v_offset;

	if (sync_ctx->need_space_seq != 0) {
		i_assert(sync_ctx->space_diff < 0);
		padding = MBOX_HEADER_PADDING *
			(sync_ctx->seq - sync_ctx->need_space_seq + 1);
		sync_ctx->space_diff -= padding;

		sync_ctx->space_diff += sync_ctx->expunged_space;
		if (sync_ctx->expunged_space <= -sync_ctx->space_diff)
			sync_ctx->expunged_space = 0;
		else
			sync_ctx->expunged_space -= -sync_ctx->space_diff;

		if (mail_ctx->have_eoh && !mail_ctx->updated)
			str_append_c(mail_ctx->header, '\n');

		if (sync_ctx->space_diff < 0 &&
		    mbox_sync_grow_file(sync_ctx, mail_ctx,
					-sync_ctx->space_diff) < 0)
			return -1;

		need_rewrite = sync_ctx->seq != sync_ctx->need_space_seq;
		if (mbox_sync_try_rewrite(mail_ctx, 0, need_rewrite) < 0)
			return -1;

		if (need_rewrite) {
			buffer_set_used_size(sync_ctx->mails,
					     (sync_ctx->seq -
					      sync_ctx->need_space_seq) *
					     sizeof(mail_ctx->mail));
			buffer_append(sync_ctx->mails, &mail_ctx->mail,
				      sizeof(mail_ctx->mail));

			if (mbox_sync_rewrite(sync_ctx, padding,
					      sync_ctx->need_space_seq,
					      sync_ctx->seq) < 0)
				return -1;
		}

		update_from_offsets(sync_ctx);

		sync_ctx->need_space_seq = 0;
		buffer_set_used_size(sync_ctx->mails, 0);
	}

	if (sync_ctx->expunged_space > 0) {
		/* copy trailer, then truncate the file */
		offset = i_stream_get_size(sync_ctx->file_input) -
			sync_ctx->expunged_space - trailer_size;

		if (mbox_move(sync_ctx, offset,
			      offset + sync_ctx->expunged_space,
			      trailer_size) < 0)
			return -1;
		if (ftruncate(sync_ctx->fd, offset + trailer_size) < 0) {
			mbox_set_syscall_error(sync_ctx->ibox, "ftruncate()");
			return -1;
		}

                sync_ctx->expunged_space = 0;
		istream_raw_mbox_flush(sync_ctx->input);
	}
	return 0;
}

static int mbox_sync_update_index_header(struct mbox_sync_context *sync_ctx)
{
	struct stat st;

	if (fstat(sync_ctx->fd, &st) < 0) {
		mbox_set_syscall_error(sync_ctx->ibox, "fstat()");
		return -1;
	}

	if ((sync_ctx->base_uid_validity != 0 &&
	     sync_ctx->base_uid_validity != sync_ctx->hdr->uid_validity) ||
	    (sync_ctx->hdr->uid_validity == 0 && sync_ctx->seen_first_mail)) {
		if (sync_ctx->base_uid_validity == 0) {
			/* we didn't rewrite X-IMAPbase header because
			   a) mbox is read-only, b) we're lazy-writing */
			i_assert(sync_ctx->delay_writes);
                        sync_ctx->base_uid_validity = time(NULL);
		}
		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, uid_validity),
			&sync_ctx->base_uid_validity,
			sizeof(sync_ctx->base_uid_validity));
	}

	if (istream_raw_mbox_is_eof(sync_ctx->input) &&
	    sync_ctx->next_uid != sync_ctx->hdr->next_uid) {
		i_assert(sync_ctx->next_uid != 0);
		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, next_uid),
			&sync_ctx->next_uid, sizeof(sync_ctx->next_uid));
	}

	if ((uint32_t)st.st_mtime != sync_ctx->hdr->sync_stamp &&
	    !sync_ctx->ibox->mbox_sync_dirty) {
		uint32_t sync_stamp = st.st_mtime;

		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp));
	}
	if ((uint64_t)st.st_size != sync_ctx->hdr->sync_size &&
	    !sync_ctx->ibox->mbox_sync_dirty) {
		uint64_t sync_size = st.st_size;

		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, sync_size),
			&sync_size, sizeof(sync_size));
	}

	sync_ctx->ibox->mbox_dirty_stamp = st.st_mtime;
	sync_ctx->ibox->mbox_dirty_size = st.st_size;

	return 0;
}

static void mbox_sync_restart(struct mbox_sync_context *sync_ctx)
{
	sync_ctx->base_uid_validity = 0;
	sync_ctx->base_uid_last = 0;

	sync_ctx->next_uid = sync_ctx->hdr->next_uid;
	sync_ctx->prev_msg_uid = 0;
	sync_ctx->seq = 0;
        sync_ctx->idx_seq = 1;

	sync_ctx->dest_first_mail = TRUE;
        sync_ctx->seen_first_mail = FALSE;
}

static int mbox_sync_do(struct mbox_sync_context *sync_ctx,
			enum mbox_sync_flags flags)
{
	struct mbox_sync_mail_context mail_ctx;
	struct stat st;
	uint32_t min_msg_count;
	int ret, partial;

	partial = FALSE;

	if ((flags & MBOX_SYNC_HEADER) != 0)
		min_msg_count = 1;
	else {
		if (fstat(sync_ctx->fd, &st) < 0) {
			mbox_set_syscall_error(sync_ctx->ibox, "stat()");
			return -1;
		}

		if ((uint32_t)st.st_mtime == sync_ctx->hdr->sync_stamp &&
		    (uint64_t)st.st_size == sync_ctx->hdr->sync_size) {
			/* file is fully synced */
			sync_ctx->ibox->mbox_sync_dirty = FALSE;
			min_msg_count = 0;
		} else if ((flags & MBOX_SYNC_UNDIRTY) != 0 ||
			   (uint64_t)st.st_size == sync_ctx->hdr->sync_size) {
			/* we want to do full syncing. always do this if
			   file size hasn't changed but timestamp has. it most
			   likely means that someone had modified some header
			   and we probably want to know about it */
			min_msg_count = (uint32_t)-1;
			sync_ctx->ibox->mbox_sync_dirty = TRUE;
		} else {
			/* see if we can delay syncing the whole file.
			   normally we only notice expunges and appends
			   in partial syncing. */
			partial = TRUE;
			min_msg_count = (uint32_t)-1;
			sync_ctx->ibox->mbox_sync_dirty = TRUE;
		}
	}

	mbox_sync_restart(sync_ctx);
	ret = mbox_sync_loop(sync_ctx, &mail_ctx, min_msg_count, partial);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* partial syncing didn't work, do it again */
		mbox_sync_restart(sync_ctx);

		mail_index_transaction_rollback(sync_ctx->t);
		sync_ctx->t = mail_index_transaction_begin(sync_ctx->sync_view,
							   FALSE);

		ret = mbox_sync_loop(sync_ctx, &mail_ctx, (uint32_t)-1, FALSE);
		if (ret <= 0) {
			i_assert(ret != 0);
			return -1;
		}
	}

	if (mbox_sync_handle_eof_updates(sync_ctx, &mail_ctx) < 0)
		return -1;

	/* only syncs left should be just appends (and their updates)
	   which weren't synced yet for some reason (crash). we'll just
	   ignore them, as we've overwritten them above. */
	buffer_set_used_size(sync_ctx->syncs, 0);
	memset(&sync_ctx->sync_rec, 0, sizeof(sync_ctx->sync_rec));

	if (mbox_sync_update_index_header(sync_ctx) < 0)
		return -1;

	return 0;
}

int mbox_sync_has_changed(struct index_mailbox *ibox, int leave_dirty)
{
	const struct mail_index_header *hdr;
	struct stat st;

	if (mail_index_get_header(ibox->view, &hdr) < 0) {
		mail_storage_set_index_error(ibox);
		return -1;
	}

	if (stat(ibox->path, &st) < 0) {
		mbox_set_syscall_error(ibox, "stat()");
		return -1;
	}

	if ((uint32_t)st.st_mtime == hdr->sync_stamp &&
	    (uint64_t)st.st_size == hdr->sync_size) {
		/* fully synced */
		ibox->mbox_sync_dirty = FALSE;
		return 0;
	}

	if (!ibox->mbox_sync_dirty || !leave_dirty)
		return 1;

	return st.st_mtime != ibox->mbox_dirty_stamp ||
		st.st_size != ibox->mbox_dirty_size;
}

static int mbox_sync_update_imap_base(struct mbox_sync_context *sync_ctx)
{
	struct mbox_sync_mail_context mail_ctx;

	if (mbox_sync_seek(sync_ctx, 0) < 0)
		return -1;

	sync_ctx->t = mail_index_transaction_begin(sync_ctx->sync_view, FALSE);
	sync_ctx->update_base_uid_last = sync_ctx->next_uid-1;

	mbox_sync_restart(sync_ctx);
	if (mbox_sync_loop(sync_ctx, &mail_ctx, 1, 0) < 0)
		return -1;

	if (mbox_sync_handle_eof_updates(sync_ctx, &mail_ctx) < 0)
		return -1;

	if (mbox_sync_update_index_header(sync_ctx) < 0)
		return -1;

	return 0;
}

int mbox_sync(struct index_mailbox *ibox, enum mbox_sync_flags flags)
{
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mbox_sync_context sync_ctx;
	uint32_t seq;
	uoff_t offset;
	unsigned int lock_id = 0;
	int ret, changed;

	ibox->sync_last_check = ioloop_time;

	if (!ibox->mbox_do_dirty_syncs)
		flags |= MBOX_SYNC_UNDIRTY;

	if ((flags & MBOX_SYNC_LOCK_READING) != 0) {
		if (mbox_lock(ibox, F_RDLCK, &lock_id) <= 0)
			return -1;
	}

	if ((flags & MBOX_SYNC_HEADER) != 0)
		changed = 1;
	else {
		int leave_dirty = (flags & MBOX_SYNC_UNDIRTY) == 0;
		if ((changed = mbox_sync_has_changed(ibox, leave_dirty)) < 0) {
			if ((flags & MBOX_SYNC_LOCK_READING) != 0)
				(void)mbox_unlock(ibox, lock_id);
			return -1;
		}
	}

	if ((flags & MBOX_SYNC_LOCK_READING) != 0) {
		/* we just want to lock it for reading. if mbox hasn't been
		   modified don't do any syncing. */
		if (!changed)
			return 0;

		/* have to sync to make sure offsets have stayed the same */
		(void)mbox_unlock(ibox, lock_id);
		lock_id = 0;
	}

__again:
	if (changed) {
		/* we're most likely modifying the mbox while syncing, just
		   lock it for writing immediately. the mbox must be locked
		   before index syncing is started to avoid deadlocks, so we
		   don't have much choice either (well, easy ones anyway). */
		int lock_type = ibox->mbox_readonly ? F_RDLCK : F_WRLCK;
		if (mbox_lock(ibox, lock_type, &lock_id) <= 0)
			return -1;
	}

	if ((flags & MBOX_SYNC_LAST_COMMIT) != 0) {
		seq = ibox->commit_log_file_seq;
		offset = ibox->commit_log_file_offset;
	} else {
		seq = (uint32_t)-1;
		offset = (uoff_t)-1;
	}

	ret = mail_index_sync_begin(ibox->index, &index_sync_ctx, &sync_view,
				    seq, offset, !ibox->keep_recent);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(ibox);
		if (lock_id != 0)
			(void)mbox_unlock(ibox, lock_id);
		return ret;
	}

	if (!changed && !mail_index_sync_have_more(index_sync_ctx)) {
		/* nothing to do */
		if (lock_id != 0)
			(void)mbox_unlock(ibox, lock_id);

		/* index may need to do internal syncing though, so commit
		   instead of rollbacking. */
		if (mail_index_sync_commit(index_sync_ctx) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}
		return 0;
	}

	if (lock_id == 0) {
		/* ok, we have something to do but no locks. we'll have to
		   restart syncing to avoid deadlocking. */
		mail_index_sync_rollback(index_sync_ctx);
		changed = 1;
		goto __again;
	}

	if (mbox_file_open_stream(ibox) < 0) {
		mail_index_sync_rollback(index_sync_ctx);
		(void)mbox_unlock(ibox, lock_id);
		return -1;
	}

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ibox = ibox;
	sync_ctx.from_line = str_new(default_pool, 256);
	sync_ctx.header = str_new(default_pool, 4096);
	sync_ctx.uidl = str_new(default_pool, 128);

	sync_ctx.index_sync_ctx = index_sync_ctx;
	sync_ctx.sync_view = sync_view;
	sync_ctx.t = mail_index_transaction_begin(sync_view, FALSE);

	sync_ctx.mails = buffer_create_dynamic(default_pool, 4096, (size_t)-1);
	sync_ctx.syncs = buffer_create_dynamic(default_pool, 256, (size_t)-1);

	ret = mail_index_get_header(sync_view, &sync_ctx.hdr);
	i_assert(ret == 0);

	sync_ctx.file_input = sync_ctx.ibox->mbox_file_stream;
	sync_ctx.input = sync_ctx.ibox->mbox_stream;
	sync_ctx.fd = sync_ctx.ibox->mbox_fd;
	sync_ctx.flags = flags;
	sync_ctx.delay_writes = sync_ctx.ibox->mbox_readonly ||
		sync_ctx.ibox->readonly ||
		((flags & MBOX_SYNC_REWRITE) == 0 &&
		 getenv("MBOX_LAZY_WRITES") != NULL);


	if (mbox_sync_do(&sync_ctx, flags) < 0)
		ret = -1;

	if (ret < 0)
		mail_index_transaction_rollback(sync_ctx.t);
	else if (mail_index_transaction_commit(sync_ctx.t, &seq, &offset) < 0) {
		mail_storage_set_index_error(ibox);
		ret = -1;
	} else {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	}
	sync_ctx.t = NULL;

	if (ret < 0)
		mail_index_sync_rollback(index_sync_ctx);
	else if (mail_index_sync_commit(index_sync_ctx) < 0) {
		mail_storage_set_index_error(ibox);
		ret = -1;
	}

	if (sync_ctx.seen_first_mail &&
	    sync_ctx.base_uid_last != sync_ctx.next_uid-1 &&
	    ret == 0 && !sync_ctx.delay_writes) {
		/* rewrite X-IMAPbase header. do it after mail_index_sync_end()
		   so previous transactions have been committed. */
		/* FIXME: ugly .. */
		ret = mail_index_sync_begin(ibox->index,
					    &sync_ctx.index_sync_ctx,
					    &sync_ctx.sync_view,
					    (uint32_t)-1, (uoff_t)-1, FALSE);
		if (ret < 0)
			mail_storage_set_index_error(ibox);
		else {
			(void)mail_index_get_header(sync_ctx.sync_view,
						    &sync_ctx.hdr);
			if ((ret = mbox_sync_update_imap_base(&sync_ctx)) < 0)
				mail_index_transaction_rollback(sync_ctx.t);
			else if (mail_index_transaction_commit(sync_ctx.t,
							       &seq,
							       &offset) < 0) {
				mail_storage_set_index_error(ibox);
				ret = -1;
			}

			if (mail_index_sync_commit(sync_ctx.
						   index_sync_ctx) < 0) {
				mail_storage_set_index_error(ibox);
				ret = -1;
			}
		}
	}

	if (ret == 0 && ibox->mbox_lock_type == F_WRLCK) {
		if (fsync(ibox->mbox_fd) < 0) {
			mbox_set_syscall_error(ibox, "fsync()");
			ret = -1;
		}
	}

	if (lock_id != 0 && ibox->mbox_lock_type != F_RDLCK) {
		/* drop to read lock */
		unsigned int read_lock_id = 0;

		if (mbox_lock(ibox, F_RDLCK, &read_lock_id) <= 0)
			ret = -1;
		else {
			if (mbox_unlock(ibox, lock_id) < 0)
				ret = -1;
			lock_id = read_lock_id;
		}
	}

	if (lock_id != 0 && (flags & MBOX_SYNC_LOCK_READING) == 0) {
		/* FIXME: keep the lock MBOX_SYNC_SECS+1 to make sure we
		   notice changes made by others .. and this has to be done
		   even if lock_reading is set.. except if
		   mbox_sync_dirty = TRUE */
		if (mbox_unlock(ibox, lock_id) < 0)
			ret = -1;
	}

	str_free(sync_ctx.uidl);
	str_free(sync_ctx.header);
	str_free(sync_ctx.from_line);
	buffer_free(sync_ctx.mails);
	buffer_free(sync_ctx.syncs);
	return ret;
}

struct mailbox_sync_context *
mbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	enum mbox_sync_flags mbox_sync_flags = 0;
	int ret = 0;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		if ((flags & MAILBOX_SYNC_FLAG_FULL_READ) != 0)
			mbox_sync_flags |= MBOX_SYNC_UNDIRTY;
		if ((flags & MAILBOX_SYNC_FLAG_FULL_WRITE) != 0)
			mbox_sync_flags |= MBOX_SYNC_REWRITE;
		ret = mbox_sync(ibox, mbox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
