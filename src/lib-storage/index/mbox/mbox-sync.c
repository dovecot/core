/* Copyright (C) 2004 Timo Sirainen */

/*
   Modifying mbox can be slow, so we try to do it all at once minimizing the
   required disk I/O. We may need to:

   - Update message flags in Status, X-Status and X-Keywords headers
   - Write missing X-UID and X-IMAPbase headers
   - Write missing or broken Content-Length header if there's space
   - Expunge specified messages

   Here's how we do it:

   - Start reading the mails mail headers from the beginning
   - X-Keywords and X-UID headers may contain extra spaces at the end of them,
     remember how much extra each message has and offset to beginning of the
     spaces
   - If message flags are dirty and there's enough space to write them, do it
   - If we didn't have enough space, remember how much was missing and keep
     the total amount of them
   - When we encounter expunged message, check if the amount of empty space in
     previous messages plus size of expunged message is enough to cover the
     missing space. If yes,
       - execute the rewrite plan
       - forget all the messages before the expunged message. only remember
         how much data we still have to move to cover the expunged message
   - If we encounter end of file, grow the file and execute the rewrite plan

   Rewrite plan goes:

   - Start from the first message that needs more space
   - If there's expunged messages before us, we have to write over them.
       - Move all messages after it backwards to fill it
       - Each moved message's X-Keywords header should have n bytes extra
         space, unless there's not enough space to do it.
   - If there's no expunged messages, we can move data either forward or
     backward to get it. Calculate which requires less moving. Forward
     counting may encounter more messages which require extra space, count
     that too.
       - If we decide to move forwards and we had to go through dirty
         messages, do the moving from last to first dirty message
   - If we encounter end of file, grow the file enough to get the required
     amount of space plus enough space to fill X-Keywords headers full of
     spaces.
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
#include <sys/stat.h>

#define MBOX_SYNC_SECS 1

/* returns -1 = error, 0 = mbox changed since previous lock, 1 = didn't */
static int mbox_sync_lock(struct mbox_sync_context *sync_ctx, int lock_type)
{
	struct index_mailbox *ibox = sync_ctx->ibox;
	struct stat old_st, st;
	uoff_t old_from_offset = 0, old_offset = 0;

	i_assert(lock_type != F_WRLCK || !ibox->mbox_readonly);

	if (sync_ctx->lock_id == 0 || sync_ctx->input == NULL) {
		memset(&old_st, 0, sizeof(old_st));
		if (sync_ctx->lock_id != 0) {
			(void)mbox_unlock(ibox, sync_ctx->lock_id);
			sync_ctx->lock_id = 0;
		}
	} else {
		if (fstat(sync_ctx->fd, &old_st) < 0) {
			mbox_set_syscall_error(ibox, "stat()");
			return -1;
		}
		old_from_offset =
			istream_raw_mbox_get_start_offset(sync_ctx->input);
		old_offset = sync_ctx->input->v_offset;

		(void)mbox_unlock(ibox, sync_ctx->lock_id);
		sync_ctx->lock_id = 0;
	}

	if (mbox_lock(ibox, lock_type, &sync_ctx->lock_id) <= 0)
		return -1;
	if (mbox_file_open_stream(ibox) < 0)
		return -1;

	sync_ctx->file_input = sync_ctx->ibox->mbox_file_stream;
	sync_ctx->input = sync_ctx->ibox->mbox_stream;
	sync_ctx->fd = sync_ctx->ibox->mbox_fd;

	if (old_st.st_mtime == 0) {
		/* we didn't have the file open before -> it changed */
		return 0;
	}

	if (fstat(sync_ctx->fd, &st) < 0) {
		mbox_set_syscall_error(ibox, "fstat()");
		return -1;
	}

	if (st.st_mtime != old_st.st_mtime || st.st_size != old_st.st_size ||
	    st.st_ino != old_st.st_ino ||
	    !CMP_DEV_T(st.st_dev, old_st.st_dev) ||
	    time(NULL) - st.st_mtime <= MBOX_SYNC_SECS)
		return 0;

	/* same as before. we'll have to fix mbox stream to contain
	   correct from_offset, hdr_offset and body_offset. so, seek
	   to from_offset and read through the header. */
	if (istream_raw_mbox_seek(sync_ctx->input, old_from_offset) < 0) {
		mail_storage_set_critical(ibox->box.storage,
			"Message offset %s changed unexpectedly for mbox file "
			"%s", dec2str(old_from_offset), sync_ctx->ibox->path);
		return 0;
	}
	(void)istream_raw_mbox_get_body_offset(sync_ctx->input);
	i_stream_seek(sync_ctx->input, old_offset);
	return 1;
}

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

	/* put the extra space between last message's header and body */
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
		if (sync[src].uid2 >= uid) {
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

	mail_ctx->from_offset =
		istream_raw_mbox_get_start_offset(sync_ctx->input);
	mail_ctx->mail.offset =
		istream_raw_mbox_get_header_offset(sync_ctx->input);

	if (mail_ctx->seq == 1)
		sync_ctx->seen_first_mail = TRUE;
	if (mail_ctx->seq > 1 && sync_ctx->dest_first_mail) {
		/* First message was expunged and this is the next one.
		   Skip \n header */
		mail_ctx->from_offset++;
	}

	mbox_sync_parse_next_mail(sync_ctx->input, mail_ctx);
	i_assert(sync_ctx->input->v_offset != mail_ctx->from_offset);

	mail_ctx->mail.body_size =
		istream_raw_mbox_get_body_size(sync_ctx->input,
					       mail_ctx->content_length);
	i_assert(mail_ctx->mail.body_size < OFF_T_MAX);

	/* save the offset permanently with recent flag state */
	mail_ctx->mail.from_offset = mail_ctx->from_offset;
	if ((mail_ctx->mail.flags & MBOX_NONRECENT) == 0) {
		if (!sync_ctx->ibox->keep_recent) {
			/* need to add 'O' flag to Status-header */
			mail_ctx->need_rewrite = TRUE;
		}
		// FIXME: save it somewhere
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

	if (sync_ctx->ibox->mbox_readonly || sync_ctx->index_sync_ctx == NULL)
		return 0;

	if (uid == 0) {
		/* nothing for this or the future ones */
		uid = (uint32_t)-1;
	}

	mbox_sync_buffer_delete_old(sync_ctx->syncs, uid);
	while (uid >= sync_rec->uid1) {
		if (uid <= sync_rec->uid2 &&
		    sync_rec->type != MAIL_INDEX_SYNC_TYPE_APPEND) {
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
		ret = 0;
	} else {
		ret = 1;
	}

	*rec_r = rec;
	return ret;
}

static int mbox_sync_get_from_offset(struct mbox_sync_context *sync_ctx,
				     uint32_t seq, uint64_t *offset_r)
{
	const void *data;

	/* see if from_offset needs updating */
	if (mail_index_lookup_extra(sync_ctx->sync_view, seq,
				    sync_ctx->ibox->mbox_extra_idx,
				    &data) < 0) {
		mail_storage_set_index_error(sync_ctx->ibox);
		return -1;
	}

	*offset_r = *((const uint64_t *)data);
	return 0;
}

static int
mbox_sync_update_from_offset(struct mbox_sync_context *sync_ctx,
                             struct mbox_sync_mail *mail,
			     int nocheck)
{
	uint64_t offset;

	if (!nocheck) {
		if (mbox_sync_get_from_offset(sync_ctx, sync_ctx->idx_seq,
					      &offset) < 0)
			return -1;

		if (offset == mail->from_offset)
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
		mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
					MODIFY_REPLACE, mbox_flags,
					mail->keywords);
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

		mbox_flags = (rec->flags & ~MAIL_FLAGS_MASK) |
			(mail->flags & (MAIL_FLAGS_MASK^MAIL_RECENT));

		if (idx_flags != mbox_flags ||
		    memcmp(idx_keywords, mail->keywords,
			   INDEX_KEYWORDS_BYTE_COUNT) != 0) {
			mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
						MODIFY_REPLACE, mbox_flags,
						mail->keywords);
		}
	}

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
	from_line_size = ctx->hdr_offset - ctx->from_offset;

	i_stream_seek(input, ctx->from_offset);
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
mbox_write_from_line(struct mbox_sync_mail_context *ctx, off_t move_diff)
{
	string_t *str = ctx->sync_ctx->from_line;

	if (pwrite_full(ctx->sync_ctx->fd, str_data(str), str_len(str),
			ctx->from_offset + move_diff) < 0) {
		mbox_set_syscall_error(ctx->sync_ctx->ibox, "pwrite_full()");
		return -1;
	}

	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 0;
}

static void update_from_offsets(struct mbox_sync_context *sync_ctx)
{
	const struct mbox_sync_mail *mails;
	uint32_t idx, idx_seq, extra_idx = sync_ctx->ibox->mbox_extra_idx;
	uint64_t offset;
	size_t size;

	mails = buffer_get_modifyable_data(sync_ctx->mails, &size);
	size /= sizeof(*mails);
	i_assert(sync_ctx->seq - sync_ctx->need_space_seq + 1 == size);

	idx = 0;
	idx_seq = sync_ctx->need_space_idx_seq;
	if (idx_seq == 0) {
		idx++; idx_seq++;
	}

	for (; idx < size; idx++, idx_seq++, mails++) {
		if (mails->uid == 0)
			continue;

		offset = mails->from_offset;
		mail_index_update_extra_rec(sync_ctx->t, idx_seq, extra_idx,
					    &offset);
	}
}

static int mbox_sync_check_excl_lock(struct mbox_sync_context *sync_ctx)
{
	int ret;

	if (sync_ctx->ibox->mbox_lock_type == F_RDLCK) {
		if ((ret = mbox_sync_lock(sync_ctx, F_WRLCK)) < 0)
			return -1;
		if (ret == 0)
			return -2;
	}
	return 0;
}

static int mbox_sync_handle_expunge(struct mbox_sync_mail_context *mail_ctx)
{
	int ret;

	if ((ret = mbox_sync_check_excl_lock(mail_ctx->sync_ctx)) < 0)
		return ret;

	mail_ctx->mail.offset = mail_ctx->from_offset;
	mail_ctx->mail.space =
		mail_ctx->body_offset - mail_ctx->from_offset +
		mail_ctx->mail.body_size;
	mail_ctx->mail.body_size = 0;

	if (mail_ctx->sync_ctx->dest_first_mail) {
		/* expunging first message, fix space to contain next
		   message's \n header too since it will be removed. */
		mail_ctx->mail.space++;
	}

	mail_ctx->sync_ctx->expunged_space += mail_ctx->mail.space;
	return 0;
}

static int mbox_sync_handle_header(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	off_t move_diff;
	int ret;

	if (sync_ctx->ibox->mbox_readonly)
		return 0;

	if (sync_ctx->expunged_space > 0 && sync_ctx->need_space_seq == 0) {
		/* move the header backwards to fill expunged space */
		if ((ret = mbox_sync_check_excl_lock(sync_ctx)) < 0)
			return ret;

		move_diff = -sync_ctx->expunged_space;

		/* read the From-line before rewriting overwrites it */
		if (mbox_read_from_line(mail_ctx) < 0)
			return -1;

		mbox_sync_update_header(mail_ctx, sync_ctx->syncs);
		if ((ret = mbox_sync_try_rewrite(mail_ctx, move_diff)) < 0)
			return -1;

		if (ret > 0) {
			/* rewrite successful, write From-line to
			   new location */
			mail_ctx->mail.from_offset += move_diff;
			mail_ctx->mail.offset += move_diff;
			if (mbox_write_from_line(mail_ctx, move_diff) < 0)
				return -1;
		}
	} else if (mail_ctx->need_rewrite ||
		   buffer_get_used_size(sync_ctx->syncs) != 0 ||
		   (mail_ctx->seq == 1 &&
		    sync_ctx->update_base_uid_last != 0)) {
		if ((ret = mbox_sync_check_excl_lock(sync_ctx)) < 0)
			return ret;

		mbox_sync_update_header(mail_ctx, sync_ctx->syncs);
		if ((ret = mbox_sync_try_rewrite(mail_ctx, 0)) < 0)
			return -1;
	} else {
		/* nothing to do */
		return 0;
	}

	if (ret == 0 && sync_ctx->need_space_seq == 0) {
		/* first mail with no space to write it */
		sync_ctx->need_space_seq = sync_ctx->seq;
		sync_ctx->need_space_idx_seq = sync_ctx->idx_seq;
		sync_ctx->space_diff = 0;

		if (sync_ctx->expunged_space > 0) {
			/* create dummy message to describe the expunged data */
			struct mbox_sync_mail mail;

			memset(&mail, 0, sizeof(mail));
			mail.offset = mail_ctx->from_offset -
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
	uoff_t extra_space;

	buffer_append(sync_ctx->mails, &mail_ctx->mail, sizeof(mail_ctx->mail));

	sync_ctx->space_diff += mail_ctx->mail.space;
	if (sync_ctx->space_diff < 0)
		return 0;

	/* we have enough space now */
	extra_space = MBOX_HEADER_EXTRA_SPACE *
		(sync_ctx->seq - sync_ctx->need_space_seq + 1);

	if (mail_ctx->mail.uid == 0 &&
	    (uoff_t)sync_ctx->space_diff > extra_space) {
		/* don't waste too much on extra spacing */
		sync_ctx->expunged_space = sync_ctx->space_diff - extra_space;
		sync_ctx->space_diff = extra_space;
	} else {
		sync_ctx->expunged_space = 0;
	}

	if (mbox_sync_rewrite(sync_ctx, sync_ctx->space_diff,
			      sync_ctx->need_space_seq, sync_ctx->seq) < 0)
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
mbox_sync_seek_to_uid(struct mbox_sync_context *sync_ctx, uint32_t uid)
{
	uint32_t seq1, seq2;
	uint64_t offset;

	if (mail_index_lookup_uid_range(sync_ctx->sync_view, uid, (uint32_t)-1,
					&seq1, &seq2) < 0) {
		mail_storage_set_index_error(sync_ctx->ibox);
		return -1;
	}

	if (seq1 == 0)
		return 0;

	if (mbox_sync_get_from_offset(sync_ctx, seq1, &offset) < 0)
		return -1;

        /* set to -1, since it's always increased later */
	sync_ctx->seq = seq1-1;
        sync_ctx->idx_seq = seq1;
	sync_ctx->dest_first_mail = sync_ctx->seq == 0;
	if (istream_raw_mbox_seek(sync_ctx->input, offset) < 0) {
		mail_storage_set_critical(sync_ctx->ibox->box.storage,
			"Cached message offset %s is invalid for mbox file %s",
			dec2str(offset), sync_ctx->ibox->path);
		mail_index_mark_corrupted(sync_ctx->ibox->index);
		return -1;
	}
        (void)istream_raw_mbox_get_body_offset(sync_ctx->input);
	return 1;
}

static int mbox_sync_loop(struct mbox_sync_context *sync_ctx,
			  struct mbox_sync_mail_context *mail_ctx,
			  uint32_t min_message_count)
{
	const struct mail_index_record *rec;
	uint32_t uid, messages_count;
	uoff_t offset;
	int ret, expunged;

	if (min_message_count != 0)
		ret = 0;
	else {
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
				return 0;
			}
		}

		sync_rec = buffer_get_data(sync_ctx->syncs, &size);
		if (size == 0)
			sync_rec = &sync_ctx->sync_rec;

		ret = mbox_sync_seek_to_uid(sync_ctx, sync_rec->uid1);
		if (ret < 0)
			return -1;
	}

	if (ret == 0) {
		if (istream_raw_mbox_seek(sync_ctx->input, 0) < 0) {
			/* doesn't begin with a From-line */
			mail_storage_set_error(sync_ctx->ibox->box.storage,
				"Mailbox isn't a valid mbox file");
			return -1;
		}
		sync_ctx->dest_first_mail = TRUE;
	}

	messages_count = mail_index_view_get_message_count(sync_ctx->sync_view);

	while ((ret = mbox_sync_read_next_mail(sync_ctx, mail_ctx)) > 0) {
		uid = mail_ctx->mail.uid;

		/* get all sync records related to this message */
		if (mbox_sync_read_index_syncs(sync_ctx, uid, &expunged) < 0)
			return -1;

		rec = NULL;
		if (uid != 0 && !mail_ctx->pseudo) {
			ret = mbox_sync_read_index_rec(sync_ctx, uid, &rec);
			if (ret < 0)
				return -1;
			if (ret == 0)
				uid = 0;
		}
		if (uid == 0) {
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

		if (!expunged) {
			ret = mbox_sync_handle_header(mail_ctx);
			sync_ctx->dest_first_mail = FALSE;
		} else {
			mail_ctx->mail.uid = 0;
			ret = mbox_sync_handle_expunge(mail_ctx);
		}
		if (ret < 0) {
			/* -1 = error, -2 = need to restart */
			return ret;
		}

		if (!expunged && !mail_ctx->pseudo) {
			if (mbox_sync_update_index(sync_ctx, mail_ctx,
						   rec) < 0)
				return -1;
		}
		sync_ctx->idx_seq++;

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
			mbox_sync_buffer_delete_old(sync_ctx->syncs, uid+1);
			if (buffer_get_used_size(sync_ctx->syncs) == 0) {
				/* if there's no sync records left,
				   we can stop */
				if (sync_ctx->sync_rec.uid1 == 0)
					break;

				/* we can skip forward to next record which
				   needs updating. */
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

	return 0;
}

static int mbox_sync_handle_eof_updates(struct mbox_sync_context *sync_ctx,
					struct mbox_sync_mail_context *mail_ctx)
{
	uoff_t offset, extra_space, trailer_size;

	if (!istream_raw_mbox_is_eof(sync_ctx->input)) {
		i_assert(sync_ctx->need_space_seq == 0);
		i_assert(sync_ctx->expunged_space == 0);
		return 0;
	}

	trailer_size = i_stream_get_size(sync_ctx->file_input) -
		sync_ctx->file_input->v_offset;

	if (sync_ctx->need_space_seq != 0) {
		i_assert(sync_ctx->space_diff < 0);
		extra_space = MBOX_HEADER_EXTRA_SPACE *
			(sync_ctx->seq - sync_ctx->need_space_seq + 1);
		sync_ctx->space_diff -= extra_space;

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

		if (mbox_sync_try_rewrite(mail_ctx, 0) < 0)
			return -1;

		if (sync_ctx->seq != sync_ctx->need_space_seq) {
			buffer_set_used_size(sync_ctx->mails,
					     (sync_ctx->seq -
					      sync_ctx->need_space_seq) *
					     sizeof(mail_ctx->mail));
			buffer_append(sync_ctx->mails, &mail_ctx->mail,
				      sizeof(mail_ctx->mail));

			if (mbox_sync_rewrite(sync_ctx, extra_space,
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
			/* we couldn't rewrite X-IMAPbase because it's
			   a read-only mbox */
			i_assert(sync_ctx->ibox->mbox_readonly);
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

	if ((uint32_t)st.st_mtime != sync_ctx->hdr->sync_stamp) {
		uint32_t sync_stamp = st.st_mtime;

		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp));
	}
	if ((uint64_t)st.st_size != sync_ctx->hdr->sync_size) {
		uint64_t sync_size = st.st_size;

		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, sync_size),
			&sync_size, sizeof(sync_size));
	}

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

static int mbox_sync_do(struct mbox_sync_context *sync_ctx, int sync_header)
{
	struct mbox_sync_mail_context mail_ctx;
	struct stat st;
	uint32_t min_msg_count;
	int ret;

	if (sync_header)
		min_msg_count = 1;
	else {
		if (fstat(sync_ctx->fd, &st) < 0) {
			mbox_set_syscall_error(sync_ctx->ibox, "stat()");
			return -1;
		}

		min_msg_count =
			(uint32_t)st.st_mtime == sync_ctx->hdr->sync_stamp &&
			(uint64_t)st.st_size == sync_ctx->hdr->sync_size ?
			0 : (uint32_t)-1;
	}

	mbox_sync_restart(sync_ctx);
	if ((ret = mbox_sync_loop(sync_ctx, &mail_ctx, min_msg_count)) == -1)
		return -1;

	if (ret == -2) {
		/* initially we had mbox read-locked, but later we needed a
		   write-lock. doing it required dropping the read lock.
		   we're here because mbox was modified before we got the
		   write-lock. so, restart the whole syncing. */
		i_assert(sync_ctx->ibox->mbox_lock_type == F_WRLCK);

		mail_index_transaction_rollback(sync_ctx->t);
		sync_ctx->t = mail_index_transaction_begin(sync_ctx->sync_view,
							   FALSE);

		mbox_sync_restart(sync_ctx);
		if (mbox_sync_loop(sync_ctx, &mail_ctx, (uint32_t)-1) < 0)
			return -1;
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

int mbox_sync_has_changed(struct index_mailbox *ibox)
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

	return (uint32_t)st.st_mtime != hdr->sync_stamp ||
		(uint64_t)st.st_size != hdr->sync_size;
}

static int mbox_sync_update_imap_base(struct mbox_sync_context *sync_ctx)
{
	struct mbox_sync_mail_context mail_ctx;

	if (mbox_sync_seek(sync_ctx, 0) < 0)
		return -1;

	sync_ctx->t = mail_index_transaction_begin(sync_ctx->sync_view, FALSE);
	sync_ctx->update_base_uid_last = sync_ctx->next_uid-1;

	if (mbox_sync_check_excl_lock(sync_ctx) == -1)
		return -1;

	mbox_sync_restart(sync_ctx);
	if (mbox_sync_loop(sync_ctx, &mail_ctx, 1) < 0)
		return -1;

	if (mbox_sync_handle_eof_updates(sync_ctx, &mail_ctx) < 0)
		return -1;

	if (mbox_sync_update_index_header(sync_ctx) < 0)
		return -1;

	return 0;
}

int mbox_sync(struct index_mailbox *ibox, int last_commit,
	      int sync_header, int lock)
{
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mbox_sync_context sync_ctx;
	uint32_t seq;
	uoff_t offset;
	unsigned int lock_id = 0;
	int ret, lock_type;

	if (lock) {
		if (mbox_lock(ibox, F_RDLCK, &lock_id) <= 0)
			return -1;
	}

	if (sync_header)
		ret = 0;
	else {
		if ((ret = mbox_sync_has_changed(ibox)) < 0) {
			if (lock)
				(void)mbox_unlock(ibox, lock_id);
			return -1;
		}
	}

	if (ret == 0 && !last_commit)
		return 0;

	if (last_commit) {
		seq = ibox->commit_log_file_seq;
		offset = ibox->commit_log_file_offset;
	} else {
		seq = (uint32_t)-1;
		offset = (uoff_t)-1;
	}

	ret = mail_index_sync_begin(ibox->index, &index_sync_ctx, &sync_view,
				    seq, offset);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(ibox);
		return ret;
	}

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ibox = ibox;
	sync_ctx.from_line = str_new(default_pool, 256);
	sync_ctx.header = str_new(default_pool, 4096);
	sync_ctx.uidl = str_new(default_pool, 128);
	sync_ctx.lock_id = lock_id;

	sync_ctx.index_sync_ctx = index_sync_ctx;
	sync_ctx.sync_view = sync_view;
	sync_ctx.t = mail_index_transaction_begin(sync_view, FALSE);

	sync_ctx.mails = buffer_create_dynamic(default_pool, 4096, (size_t)-1);
	sync_ctx.syncs = buffer_create_dynamic(default_pool, 256, (size_t)-1);

	ret = mail_index_get_header(sync_view, &sync_ctx.hdr);
	i_assert(ret == 0);

	lock_type = mail_index_sync_have_more(index_sync_ctx) &&
		!ibox->mbox_readonly ? F_WRLCK : F_RDLCK;
	if (lock_type == F_WRLCK && lock) {
		(void)mbox_unlock(ibox, lock_id);
		lock_id = 0;
	}

	if (mbox_sync_lock(&sync_ctx, lock_type) < 0)
		ret = -1;
	else if (mbox_sync_do(&sync_ctx, sync_header) < 0)
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

	if (mail_index_sync_end(index_sync_ctx) < 0) {
		mail_storage_set_index_error(ibox);
		ret = -1;
	}

	if (sync_ctx.seen_first_mail &&
	    sync_ctx.base_uid_last != sync_ctx.next_uid-1 &&
	    ret == 0 && !ibox->mbox_readonly) {
		/* rewrite X-IMAPbase header. do it after mail_index_sync_end()
		   so previous transactions have been committed. */
		/* FIXME: ugly .. */
		ret = mail_index_sync_begin(ibox->index,
					    &sync_ctx.index_sync_ctx,
					    &sync_ctx.sync_view,
					    (uint32_t)-1, (uoff_t)-1);
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

			if (mail_index_sync_end(sync_ctx.index_sync_ctx) < 0) {
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

	if (sync_ctx.lock_id != 0 && ibox->mbox_lock_type != F_RDLCK) {
		/* drop to read lock */
		unsigned int lock_id = 0;

		if (mbox_lock(ibox, F_RDLCK, &lock_id) <= 0)
			ret = -1;
		else {
			if (mbox_unlock(ibox, sync_ctx.lock_id) < 0)
				ret = -1;
			sync_ctx.lock_id = lock_id;
		}
	}

	if (sync_ctx.lock_id != 0 && !lock) {
		/* FIXME: keep the lock MBOX_SYNC_SECS+1 to make sure we
		   notice changes made by others */
		if (mbox_unlock(ibox, sync_ctx.lock_id) < 0)
			ret = -1;
	}

	str_free(sync_ctx.uidl);
	str_free(sync_ctx.header);
	str_free(sync_ctx.from_line);
	buffer_free(sync_ctx.mails);
	buffer_free(sync_ctx.syncs);
	return ret;
}

int mbox_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		ibox->sync_last_check = ioloop_time;

		if (mbox_sync(ibox, FALSE, FALSE, FALSE) < 0)
			return -1;
	}

	return index_storage_sync(box, flags);
}
