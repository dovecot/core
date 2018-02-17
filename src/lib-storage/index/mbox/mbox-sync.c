/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

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
#include "array.h"
#include "buffer.h"
#include "hostpid.h"
#include "istream.h"
#include "file-set-size.h"
#include "str.h"
#include "read-full.h"
#include "write-full.h"
#include "message-date.h"
#include "istream-raw-mbox.h"
#include "mbox-storage.h"
#include "index-sync-changes.h"
#include "mailbox-uidvalidity.h"
#include "mailbox-recent-flags.h"
#include "mbox-from.h"
#include "mbox-file.h"
#include "mbox-lock.h"
#include "mbox-sync-private.h"

#include <stddef.h>
#include <utime.h>
#include <sys/stat.h>

/* The text below was taken exactly as c-client wrote it to my mailbox,
   so it's probably copyrighted by University of Washington. */
#define PSEUDO_MESSAGE_BODY \
"This text is part of the internal format of your mail folder, and is not\n" \
"a real message.  It is created automatically by the mail system software.\n" \
"If deleted, important folder data will be lost, and it will be re-created\n" \
"with the data reset to initial values.\n"

void mbox_sync_set_critical(struct mbox_sync_context *sync_ctx,
			    const char *fmt, ...)
{
	va_list va;

	sync_ctx->errors = TRUE;
	if (sync_ctx->ext_modified) {
		mailbox_set_critical(&sync_ctx->mbox->box,
			"mbox was modified while we were syncing, "
			"check your locking settings");
	}

	va_start(va, fmt);
	mailbox_set_critical(&sync_ctx->mbox->box,
			     "Sync failed for mbox: %s",
			     t_strdup_vprintf(fmt, va));
	va_end(va);
}

int mbox_sync_seek(struct mbox_sync_context *sync_ctx, uoff_t from_offset)
{
	if (istream_raw_mbox_seek(sync_ctx->input, from_offset) < 0) {
		mbox_sync_set_critical(sync_ctx,
			"Unexpectedly lost From-line at offset %"PRIuUOFF_T,
			from_offset);
		return -1;
	}
	return 0;
}

void mbox_sync_file_update_ext_modified(struct mbox_sync_context *sync_ctx)
{
	struct stat st;

	/* Do this even if ext_modified is already set. Expunging code relies
	   on last_stat being updated. */
	if (fstat(sync_ctx->write_fd, &st) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "fstat()");
		return;
	}

	if (st.st_size != sync_ctx->last_stat.st_size ||
	    (sync_ctx->last_stat.st_mtime != 0 &&
	     !CMP_ST_MTIME(&st, &sync_ctx->last_stat)))
		sync_ctx->ext_modified = TRUE;

	sync_ctx->last_stat = st;
}

void mbox_sync_file_updated(struct mbox_sync_context *sync_ctx, bool dirty)
{
	if (dirty) {
		/* just mark the stat as dirty. */
		sync_ctx->last_stat.st_mtime = 0;
		return;
	}
	if (fstat(sync_ctx->write_fd, &sync_ctx->last_stat) < 0)
		mbox_set_syscall_error(sync_ctx->mbox, "fstat()");
	i_stream_sync(sync_ctx->input);
}

static int
mbox_sync_read_next_mail(struct mbox_sync_context *sync_ctx,
			 struct mbox_sync_mail_context *mail_ctx)
{
	uoff_t offset;

	/* get EOF */
	(void)istream_raw_mbox_get_header_offset(sync_ctx->input, &offset);
	if (istream_raw_mbox_is_eof(sync_ctx->input))
		return 0;

	p_clear(sync_ctx->mail_keyword_pool);
	i_zero(mail_ctx);
	mail_ctx->sync_ctx = sync_ctx;
	mail_ctx->seq = ++sync_ctx->seq;
	mail_ctx->header = sync_ctx->header;

	mail_ctx->mail.from_offset =
		istream_raw_mbox_get_start_offset(sync_ctx->input);
	if (istream_raw_mbox_get_header_offset(sync_ctx->input, &mail_ctx->mail.offset) < 0) {
		mbox_sync_set_critical(sync_ctx,
			"Couldn't get header offset for seq=%u", mail_ctx->seq);
		return -1;
	}

	if (mbox_sync_parse_next_mail(sync_ctx->input, mail_ctx) < 0)
		return -1;
	if (istream_raw_mbox_is_corrupted(sync_ctx->input))
		return -1;

	i_assert(sync_ctx->input->v_offset != mail_ctx->mail.from_offset ||
		 sync_ctx->input->eof);

	if (istream_raw_mbox_get_body_size(sync_ctx->input,
					   mail_ctx->content_length,
					   &mail_ctx->mail.body_size) < 0) {
		mbox_sync_set_critical(sync_ctx,
			"Couldn't get body size for seq=%u", mail_ctx->seq);
		return -1;
	}
	i_assert(mail_ctx->mail.body_size < OFF_T_MAX);

	if ((mail_ctx->mail.flags & MAIL_RECENT) != 0 &&
	    !mail_ctx->mail.pseudo) {
		if (!sync_ctx->keep_recent) {
			/* need to add 'O' flag to Status-header */
			mail_ctx->need_rewrite = TRUE;
		}
		mail_ctx->recent = TRUE;
	}
	return 1;
}

static void mbox_sync_read_index_syncs(struct mbox_sync_context *sync_ctx,
				       uint32_t uid, bool *sync_expunge_r)
{
	guid_128_t expunged_guid_128;

	if (uid == 0 || sync_ctx->index_reset) {
		/* nothing for this or the future ones */
		uid = (uint32_t)-1;
	}

	index_sync_changes_read(sync_ctx->sync_changes, uid, sync_expunge_r,
				expunged_guid_128);
	if (sync_ctx->readonly) {
		/* we can't expunge anything from read-only mboxes */
		*sync_expunge_r = FALSE;
	}
}

static bool
mbox_sync_read_index_rec(struct mbox_sync_context *sync_ctx,
			 uint32_t uid, const struct mail_index_record **rec_r)
{
        const struct mail_index_record *rec = NULL;
	uint32_t messages_count;
	bool ret = FALSE;

	if (sync_ctx->index_reset) {
		*rec_r = NULL;
		return TRUE;
	}

	messages_count =
		mail_index_view_get_messages_count(sync_ctx->sync_view);
	while (sync_ctx->idx_seq <= messages_count) {
		rec = mail_index_lookup(sync_ctx->sync_view, sync_ctx->idx_seq);
		if (uid <= rec->uid)
			break;

		/* externally expunged message, remove from index */
		mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq);
                sync_ctx->idx_seq++;
		rec = NULL;
	}

	if (rec == NULL && uid < sync_ctx->idx_next_uid) {
		/* this UID was already in index and it was expunged */
		mbox_sync_set_critical(sync_ctx,
			"Expunged message reappeared to mailbox "
			"(UID %u < %u, seq=%u, idx_msgs=%u)",
			uid, sync_ctx->idx_next_uid,
			sync_ctx->seq, messages_count);
		ret = FALSE; rec = NULL;
	} else if (rec != NULL && rec->uid != uid) {
		/* new UID in the middle of the mailbox - shouldn't happen */
		mbox_sync_set_critical(sync_ctx,
			"UID inserted in the middle of mailbox "
			"(%u > %u, seq=%u, idx_msgs=%u)",
			rec->uid, uid, sync_ctx->seq, messages_count);
		ret = FALSE; rec = NULL;
	} else {
		ret = TRUE;
	}

	*rec_r = rec;
	return ret;
}

static void mbox_sync_find_index_md5(struct mbox_sync_context *sync_ctx,
				     unsigned char hdr_md5_sum[],
				     const struct mail_index_record **rec_r)
{
        const struct mail_index_record *rec = NULL;
	uint32_t messages_count;
	const void *data;

	if (sync_ctx->index_reset) {
		*rec_r = NULL;
		return;
	}

	messages_count =
		mail_index_view_get_messages_count(sync_ctx->sync_view);
	while (sync_ctx->idx_seq <= messages_count) {
		rec = mail_index_lookup(sync_ctx->sync_view, sync_ctx->idx_seq);
		mail_index_lookup_ext(sync_ctx->sync_view,
				      sync_ctx->idx_seq,
				      sync_ctx->mbox->md5hdr_ext_idx,
				      &data, NULL);
		if (data != NULL && memcmp(data, hdr_md5_sum, 16) == 0)
			break;

		/* externally expunged message, remove from index */
		mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq);
                sync_ctx->idx_seq++;
		rec = NULL;
	}

	*rec_r = rec;
}

static void
mbox_sync_update_from_offset(struct mbox_sync_context *sync_ctx,
                             struct mbox_sync_mail *mail,
			     bool nocheck)
{
	const void *data;
	uint64_t offset;

	if (!nocheck) {
		/* see if from_offset needs updating */
		mail_index_lookup_ext(sync_ctx->sync_view, sync_ctx->idx_seq,
				      sync_ctx->mbox->mbox_ext_idx,
				      &data, NULL);
		if (data != NULL &&
		    *((const uint64_t *)data) == mail->from_offset)
			return;
	}

	offset = mail->from_offset;
	mail_index_update_ext(sync_ctx->t, sync_ctx->idx_seq,
			      sync_ctx->mbox->mbox_ext_idx, &offset, NULL);
}

static void
mbox_sync_update_index_keywords(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	struct mail_index *index = sync_ctx->mbox->box.index;
	struct mail_keywords *keywords;

	keywords = !array_is_created(&mail_ctx->mail.keywords) ?
		mail_index_keywords_create(index, NULL) :
		mail_index_keywords_create_from_indexes(index,
			&mail_ctx->mail.keywords);
	mail_index_update_keywords(sync_ctx->t, sync_ctx->idx_seq,
				   MODIFY_REPLACE, keywords);
	mail_index_keywords_unref(&keywords);
}

static void
mbox_sync_update_md5_if_changed(struct mbox_sync_mail_context *mail_ctx)
{
        struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	const void *ext_data;

	mail_index_lookup_ext(sync_ctx->sync_view, sync_ctx->idx_seq,
			      sync_ctx->mbox->md5hdr_ext_idx, &ext_data, NULL);
	if (ext_data == NULL ||
	    memcmp(mail_ctx->hdr_md5_sum, ext_data, 16) != 0) {
		mail_index_update_ext(sync_ctx->t, sync_ctx->idx_seq,
				      sync_ctx->mbox->md5hdr_ext_idx,
				      mail_ctx->hdr_md5_sum, NULL);
	}
}

static void mbox_sync_get_dirty_flags(struct mbox_sync_mail_context *mail_ctx,
				      const struct mail_index_record *rec)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	ARRAY_TYPE(keyword_indexes) idx_keywords;
	uint8_t idx_flags, mbox_flags;

	/* default to undirtying the message. it gets added back if
	   flags/keywords don't match what is in the index. */
	mail_ctx->mail.flags &= ~MAIL_INDEX_MAIL_FLAG_DIRTY;

	/* replace flags */
	idx_flags = rec->flags & MAIL_FLAGS_NONRECENT;
	mbox_flags = mail_ctx->mail.flags & MAIL_FLAGS_NONRECENT;
	if (idx_flags != mbox_flags) {
		mail_ctx->need_rewrite = TRUE;
		mail_ctx->mail.flags = (mail_ctx->mail.flags & MAIL_RECENT) |
			idx_flags | MAIL_INDEX_MAIL_FLAG_DIRTY;
	}

	/* replace keywords */
	t_array_init(&idx_keywords, 32);
	mail_index_lookup_keywords(sync_ctx->sync_view, sync_ctx->idx_seq,
				   &idx_keywords);
	if (!index_keyword_array_cmp(&idx_keywords, &mail_ctx->mail.keywords)) {
		mail_ctx->need_rewrite = TRUE;
		mail_ctx->mail.flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;

		if (!array_is_created(&mail_ctx->mail.keywords)) {
			p_array_init(&mail_ctx->mail.keywords,
				     sync_ctx->mail_keyword_pool,
				     array_count(&idx_keywords));
		}
		array_clear(&mail_ctx->mail.keywords);
		array_append_array(&mail_ctx->mail.keywords, &idx_keywords);
	}
}

static void mbox_sync_update_flags(struct mbox_sync_mail_context *mail_ctx,
				   const struct mail_index_record *rec)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	struct mailbox *box = &sync_ctx->mbox->box;
	struct mbox_sync_mail *mail = &mail_ctx->mail;
	enum mail_index_sync_type sync_type;
	ARRAY_TYPE(keyword_indexes) orig_keywords = ARRAY_INIT;
	uint8_t flags, orig_flags;

	if (rec != NULL) {
		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* flags and keywords are dirty. replace the current
			   ones from the flags in index file. */
			mbox_sync_get_dirty_flags(mail_ctx, rec);
		}
	}

	flags = orig_flags = mail->flags & MAIL_FLAGS_NONRECENT;
	if (array_is_created(&mail->keywords)) {
		t_array_init(&orig_keywords, 32);
		array_append_array(&orig_keywords, &mail->keywords);
	}

	/* apply new changes */
	index_sync_changes_apply(sync_ctx->sync_changes,
				 sync_ctx->mail_keyword_pool,
				 &flags, &mail->keywords, &sync_type);
	if (flags != orig_flags ||
	    !index_keyword_array_cmp(&mail->keywords, &orig_keywords)) {
		mail_ctx->need_rewrite = TRUE;
		mail->flags = flags | (mail->flags & MAIL_RECENT) |
			MAIL_INDEX_MAIL_FLAG_DIRTY;
	}
	if (sync_type != 0 && box->v.sync_notify != NULL) {
		box->v.sync_notify(box, mail_ctx->mail.uid,
				   index_sync_type_convert(sync_type));
	}
}

static void mbox_sync_update_index(struct mbox_sync_mail_context *mail_ctx,
				   const struct mail_index_record *rec)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	struct mbox_sync_mail *mail = &mail_ctx->mail;
	ARRAY_TYPE(keyword_indexes) idx_keywords;
	uint8_t mbox_flags;

	mbox_flags = mail->flags & ~MAIL_RECENT;
	if (!sync_ctx->delay_writes) {
		/* changes are written to the mbox file */
		mbox_flags &= ~MAIL_INDEX_MAIL_FLAG_DIRTY;
	} else if (mail_ctx->need_rewrite) {
		/* make sure this message gets written later */
		mbox_flags |= MAIL_INDEX_MAIL_FLAG_DIRTY;
	}

	if (rec == NULL) {
		/* new message */
		mail_index_append(sync_ctx->t, mail->uid, &sync_ctx->idx_seq);
		mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
					MODIFY_REPLACE, mbox_flags);
		mbox_sync_update_index_keywords(mail_ctx);

		if (sync_ctx->mbox->mbox_save_md5) {
			mail_index_update_ext(sync_ctx->t, sync_ctx->idx_seq,
				sync_ctx->mbox->md5hdr_ext_idx,
				mail_ctx->hdr_md5_sum, NULL);
		}
	} else {
		if ((rec->flags & MAIL_FLAGS_NONRECENT) !=
		    (mbox_flags & MAIL_FLAGS_NONRECENT)) {
			/* flags other than recent/dirty have changed */
			mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
						MODIFY_REPLACE, mbox_flags);
		} else if (((rec->flags ^ mbox_flags) &
			    MAIL_INDEX_MAIL_FLAG_DIRTY) != 0) {
			/* only dirty flag state changed */
			bool dirty;

			dirty = (mbox_flags & MAIL_INDEX_MAIL_FLAG_DIRTY) != 0;
			mail_index_update_flags(sync_ctx->t, sync_ctx->idx_seq,
				dirty ? MODIFY_ADD : MODIFY_REMOVE,
				(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
		}

		/* see if keywords changed */
		t_array_init(&idx_keywords, 32);
		mail_index_lookup_keywords(sync_ctx->sync_view,
					   sync_ctx->idx_seq, &idx_keywords);
		if (!index_keyword_array_cmp(&idx_keywords, &mail->keywords))
			mbox_sync_update_index_keywords(mail_ctx);

		/* see if we need to update md5 sum. */
		if (sync_ctx->mbox->mbox_save_md5)
			mbox_sync_update_md5_if_changed(mail_ctx);
	}

	if (!mail_ctx->recent) {
		/* Mail has "Status: O" header. No messages before this
		   can be recent. */
		sync_ctx->last_nonrecent_uid = mail->uid;
	}

	/* update from_offsets, but not if we're going to rewrite this message.
	   rewriting would just move it anyway. */
	if (sync_ctx->need_space_seq == 0) {
		bool nocheck = rec == NULL || sync_ctx->expunged_space > 0;
		mbox_sync_update_from_offset(sync_ctx, mail, nocheck);
	}
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

static int mbox_rewrite_base_uid_last(struct mbox_sync_context *sync_ctx)
{
	unsigned char buf[10];
	const char *str;
	uint32_t uid_last;
	unsigned int i;
	int ret;

	i_assert(sync_ctx->base_uid_last_offset != 0);

	/* first check that the 10 bytes are there and they're exactly as
	   expected. just an extra safety check to make sure we never write
	   to wrong location in the mbox file. */
	ret = pread_full(sync_ctx->write_fd, buf, sizeof(buf),
			 sync_ctx->base_uid_last_offset);
	if (ret < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pread_full()");
		return -1;
	}
	if (ret == 0) {
		mbox_sync_set_critical(sync_ctx,
			"X-IMAPbase uid-last offset unexpectedly outside mbox");
		return -1;
	}

	for (i = 0, uid_last = 0; i < sizeof(buf); i++) {
		if (buf[i] < '0' || buf[i] > '9') {
			uid_last = (uint32_t)-1;
			break;
		}
		uid_last = uid_last * 10 + (buf[i] - '0');
	}

	if (uid_last != sync_ctx->base_uid_last) {
		mbox_sync_set_critical(sync_ctx,
			"X-IMAPbase uid-last unexpectedly lost");
		return -1;
	}

	/* and write it */
	str = t_strdup_printf("%010u", sync_ctx->next_uid - 1);
	if (pwrite_full(sync_ctx->write_fd, str, 10,
			sync_ctx->base_uid_last_offset) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pwrite_full()");
		return -1;
	}
	mbox_sync_file_updated(sync_ctx, FALSE);

	sync_ctx->base_uid_last = sync_ctx->next_uid - 1;
	return 0;
}

static int
mbox_write_from_line(struct mbox_sync_mail_context *ctx)
{
	string_t *str = ctx->sync_ctx->from_line;

	if (pwrite_full(ctx->sync_ctx->write_fd, str_data(str), str_len(str),
			ctx->mail.from_offset) < 0) {
		mbox_set_syscall_error(ctx->sync_ctx->mbox, "pwrite_full()");
		return -1;
	}

	mbox_sync_file_updated(ctx->sync_ctx, FALSE);
	return 0;
}

static void update_from_offsets(struct mbox_sync_context *sync_ctx)
{
	const struct mbox_sync_mail *mails;
	unsigned int i, count;
	uint32_t ext_idx;
	uint64_t offset;

	ext_idx = sync_ctx->mbox->mbox_ext_idx;

	mails = array_get(&sync_ctx->mails, &count);
	for (i = 0; i < count; i++) {
		if (mails[i].idx_seq == 0 || mails[i].expunged)
			continue;

		sync_ctx->moved_offsets = TRUE;
		offset = mails[i].from_offset;
		mail_index_update_ext(sync_ctx->t, mails[i].idx_seq,
				      ext_idx, &offset, NULL);
	}
}

static void mbox_sync_handle_expunge(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	struct mailbox *box = &sync_ctx->mbox->box;

	if (box->v.sync_notify != NULL) {
		box->v.sync_notify(box, mail_ctx->mail.uid,
				   MAILBOX_SYNC_TYPE_EXPUNGE);
	}
	mail_index_expunge(sync_ctx->t, mail_ctx->mail.idx_seq);

	mail_ctx->mail.expunged = TRUE;
	mail_ctx->mail.offset = mail_ctx->mail.from_offset;
	mail_ctx->mail.space =
		mail_ctx->body_offset - mail_ctx->mail.from_offset +
		mail_ctx->mail.body_size;
	mail_ctx->mail.body_size = 0;
	mail_ctx->mail.uid = 0;

	if (sync_ctx->seq == 1) {
		/* expunging first message, fix space to contain next
		   message's \n header too since it will be removed. */
		mail_ctx->mail.space++;
		if (istream_raw_mbox_has_crlf_ending(sync_ctx->input)) {
			mail_ctx->mail.space++;
			sync_ctx->first_mail_crlf_expunged = TRUE;
		}

		/* uid-last offset is invalid now */
                sync_ctx->base_uid_last_offset = 0;
	}

	sync_ctx->expunged_space += mail_ctx->mail.space;
}

static int mbox_sync_handle_header(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	uoff_t orig_from_offset, postlf_from_offset = (uoff_t)-1;
	off_t move_diff;
	int ret;

	if (sync_ctx->expunged_space > 0 && sync_ctx->need_space_seq == 0) {
		/* move the header backwards to fill expunged space */
		move_diff = -sync_ctx->expunged_space;

		orig_from_offset = mail_ctx->mail.from_offset;
		if (sync_ctx->dest_first_mail) {
			/* we're moving this mail to beginning of file.
			   skip the initial \n (it's already counted in
			   expunged_space) */
			mail_ctx->mail.from_offset++;
			if (sync_ctx->first_mail_crlf_expunged)
				mail_ctx->mail.from_offset++;
		}
		postlf_from_offset = mail_ctx->mail.from_offset;

		/* read the From-line before rewriting overwrites it */
		if (mbox_read_from_line(mail_ctx) < 0)
			return -1;
		i_assert(mail_ctx->mail.from_offset + move_diff != 1 &&
			 mail_ctx->mail.from_offset + move_diff != 2);

		mbox_sync_update_header(mail_ctx);
		ret = mbox_sync_try_rewrite(mail_ctx, move_diff);
		if (ret < 0)
			return -1;

		if (ret > 0) {
			/* rewrite successful, write From-line to
			   new location */
			i_assert((off_t)mail_ctx->mail.from_offset >=
				 -move_diff);
			mail_ctx->mail.from_offset += move_diff;
			mail_ctx->mail.offset += move_diff;
			if (mbox_write_from_line(mail_ctx) < 0)
				return -1;
		} else {
			if (sync_ctx->dest_first_mail) {
				/* didn't have enough space, move the offset
				   back so seeking into it doesn't fail */
				mail_ctx->mail.from_offset = orig_from_offset;
			}
		}
	} else if (mail_ctx->need_rewrite) {
		mbox_sync_update_header(mail_ctx);
		if (sync_ctx->delay_writes && sync_ctx->need_space_seq == 0) {
			/* mark it dirty and do it later. we can't do this
			   if we're in the middle of rewriting acquiring more
			   space. */
			mail_ctx->dirty = TRUE;
			return 0;
		}

		if ((ret = mbox_sync_try_rewrite(mail_ctx, 0)) < 0)
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

			/* if this is going to be the first mail, increase the
			   from_offset to point to the beginning of the
			   From-line, because the previous [CR]LF is already
			   covered by expunged_space. */
			i_assert(postlf_from_offset != (uoff_t)-1);
			mail_ctx->mail.from_offset = postlf_from_offset;

			i_zero(&mail);
			mail.expunged = TRUE;
			mail.offset = mail.from_offset =
				mail_ctx->mail.from_offset -
				sync_ctx->expunged_space;
			mail.space = sync_ctx->expunged_space;

                        sync_ctx->space_diff = sync_ctx->expunged_space;
			sync_ctx->expunged_space = 0;
			i_assert(sync_ctx->space_diff < -mail_ctx->mail.space);

			sync_ctx->need_space_seq--;
			array_push_back(&sync_ctx->mails, &mail);
		}
	}
	return 0;
}

static int
mbox_sync_handle_missing_space(struct mbox_sync_mail_context *mail_ctx)
{
	struct mbox_sync_context *sync_ctx = mail_ctx->sync_ctx;
	uoff_t end_offset, move_diff, extra_space, needed_space;
	uint32_t last_seq;
	ARRAY_TYPE(keyword_indexes) keywords_copy;

	i_assert(mail_ctx->mail.uid == 0 || mail_ctx->mail.space > 0 ||
		 mail_ctx->mail.offset == mail_ctx->hdr_offset);

	if (array_is_created(&mail_ctx->mail.keywords)) {
		/* mail's keywords are allocated from a pool that's cleared
		   for each mail. we'll need to copy it to something more
		   permanent. */
		p_array_init(&keywords_copy, sync_ctx->saved_keywords_pool,
			     array_count(&mail_ctx->mail.keywords));
		array_append_array(&keywords_copy, &mail_ctx->mail.keywords);
		mail_ctx->mail.keywords = keywords_copy;
	}
	array_push_back(&sync_ctx->mails, &mail_ctx->mail);

	sync_ctx->space_diff += mail_ctx->mail.space;
	if (sync_ctx->space_diff < 0) {
		if (sync_ctx->expunged_space > 0) {
			i_assert(sync_ctx->expunged_space ==
				 mail_ctx->mail.space);
                        sync_ctx->expunged_space = 0;
		}
		return 0;
	}

	/* we have enough space now */
	if (mail_ctx->mail.uid == 0) {
		/* this message was expunged. fill more or less of the space.
		   space_diff now consists of a negative "bytes needed" sum,
		   plus the expunged space of this message. so it contains how
		   many bytes of _extra_ space we have. */
		i_assert(mail_ctx->mail.space >= sync_ctx->space_diff);
		extra_space = MBOX_HEADER_PADDING *
			(sync_ctx->seq - sync_ctx->need_space_seq + 1);
		needed_space = mail_ctx->mail.space - sync_ctx->space_diff;
		if ((uoff_t)sync_ctx->space_diff > needed_space + extra_space) {
			/* don't waste too much on padding */
			move_diff = needed_space + extra_space;
			sync_ctx->expunged_space =
				mail_ctx->mail.space - move_diff;
		} else {
			move_diff = mail_ctx->mail.space;
			extra_space = sync_ctx->space_diff;
			sync_ctx->expunged_space = 0;
		}
		last_seq = sync_ctx->seq - 1;
		array_pop_back(&sync_ctx->mails);
		end_offset = mail_ctx->mail.from_offset;
	} else {
		/* this message gave enough space from headers. rewriting stops
		   at the end of this message's headers. */
		sync_ctx->expunged_space = 0;
		last_seq = sync_ctx->seq;
		end_offset = mail_ctx->body_offset;

		move_diff = 0;
		extra_space = sync_ctx->space_diff;
	}

	mbox_sync_file_update_ext_modified(sync_ctx);
	if (mbox_sync_rewrite(sync_ctx,
			      last_seq == sync_ctx->seq ? mail_ctx : NULL,
			      end_offset, move_diff, extra_space,
			      sync_ctx->need_space_seq, last_seq) < 0)
		return -1;

	update_from_offsets(sync_ctx);

	/* mail_ctx may contain wrong data after rewrite, so make sure we
	   don't try to access it */
	i_zero(mail_ctx);

	sync_ctx->need_space_seq = 0;
	sync_ctx->space_diff = 0;
	array_clear(&sync_ctx->mails);
	p_clear(sync_ctx->saved_keywords_pool);
	return 0;
}

static int
mbox_sync_seek_to_seq(struct mbox_sync_context *sync_ctx, uint32_t seq)
{
	struct mbox_mailbox *mbox = sync_ctx->mbox;
	uoff_t old_offset, offset;
	uint32_t uid;
	int ret;
        bool deleted;

	if (seq == 0) {
		if (istream_raw_mbox_seek(mbox->mbox_stream, 0) < 0) {
			mbox->invalid_mbox_file = TRUE;
			mail_storage_set_error(&mbox->storage->storage,
				MAIL_ERROR_NOTPOSSIBLE,
				"Mailbox isn't a valid mbox file");
			return -1;
		}
		seq++;
	} else {
		old_offset = istream_raw_mbox_get_start_offset(sync_ctx->input);

		ret = mbox_file_seek(mbox, sync_ctx->sync_view, seq, &deleted);
		if (ret < 0) {
			if (deleted) {
				mbox_sync_set_critical(sync_ctx,
					"Message was expunged unexpectedly");
			}
			return -1;
		}
		if (ret == 0) {
			if (istream_raw_mbox_seek(mbox->mbox_stream,
						  old_offset) < 0) {
				mbox_sync_set_critical(sync_ctx,
					"Error seeking back to original "
					"offset %s", dec2str(old_offset));
				return -1;
			}
			return 0;
		}
	}

	if (seq <= 1)
		uid = 0;
	else
		mail_index_lookup_uid(sync_ctx->sync_view, seq-1, &uid);

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
	if (istream_raw_mbox_get_body_offset(sync_ctx->input, &offset) < 0) {
		mbox_sync_set_critical(sync_ctx,
			"Message body offset lookup failed");
		return -1;
	}
	return 1;
}

static int
mbox_sync_seek_to_uid(struct mbox_sync_context *sync_ctx, uint32_t uid)
{
	struct mail_index_view *sync_view = sync_ctx->sync_view;
	uint32_t seq1, seq2;
	uoff_t size;
	int ret;

	i_assert(!sync_ctx->index_reset);

	if (!mail_index_lookup_seq_range(sync_view, uid, (uint32_t)-1,
					 &seq1, &seq2)) {
		/* doesn't exist anymore, seek to end of file */
		ret = i_stream_get_size(sync_ctx->file_input, TRUE, &size);
		if (ret < 0) {
			mbox_set_syscall_error(sync_ctx->mbox,
					       "i_stream_get_size()");
			return -1;
		}
		i_assert(ret != 0);

		if (istream_raw_mbox_seek(sync_ctx->mbox->mbox_stream,
					  size) < 0) {
			mbox_sync_set_critical(sync_ctx,
				"Error seeking to end of mbox");
			return -1;
		}
		sync_ctx->idx_seq =
			mail_index_view_get_messages_count(sync_view) + 1;
		return 1;
	}

	return mbox_sync_seek_to_seq(sync_ctx, seq1);
}

static int mbox_sync_partial_seek_next(struct mbox_sync_context *sync_ctx,
				       uint32_t next_uid, bool *partial,
				       bool *skipped_mails)
{
	uint32_t messages_count, uid;
	int ret;

	i_assert(!sync_ctx->index_reset);

	/* delete sync records up to next message. so if there's still
	   something left in array, it means the next message needs modifying */
	index_sync_changes_delete_to(sync_ctx->sync_changes, next_uid);
	if (index_sync_changes_have(sync_ctx->sync_changes))
		return 1;

	if (sync_ctx->hdr->first_recent_uid <= next_uid &&
	    !sync_ctx->keep_recent) {
		/* we'll need to rewrite Status: O headers */
		return 1;
	}

	uid = index_sync_changes_get_next_uid(sync_ctx->sync_changes);

	if (sync_ctx->hdr->first_recent_uid < sync_ctx->hdr->next_uid &&
	    (uid > sync_ctx->hdr->first_recent_uid || uid == 0) &&
	    !sync_ctx->keep_recent) {
		/* we'll need to rewrite Status: O headers */
		uid = sync_ctx->hdr->first_recent_uid;
	}

	if (uid != 0) {
		/* we can skip forward to next record which needs updating. */
		if (uid != next_uid) {
			*skipped_mails = TRUE;
			next_uid = uid;
		}
		ret = mbox_sync_seek_to_uid(sync_ctx, next_uid);
	} else {
		/* if there's no sync records left, we can stop. except if
		   this is a dirty sync, check if there are new messages. */
		if (sync_ctx->mbox->mbox_hdr.dirty_flag == 0)
			return 0;

		messages_count =
			mail_index_view_get_messages_count(sync_ctx->sync_view);
		if (sync_ctx->seq + 1 != messages_count) {
			ret = mbox_sync_seek_to_seq(sync_ctx, messages_count);
			*skipped_mails = TRUE;
		} else {
			ret = 1;
		}
		*partial = FALSE;
	}

	if (ret == 0) {
		/* seek failed because the offset is dirty. just ignore and
		   continue from where we are now. */
		*partial = FALSE;
		ret = 1;
	}
	return ret;
}

static void mbox_sync_hdr_update(struct mbox_sync_context *sync_ctx,
				 struct mbox_sync_mail_context *mail_ctx)
{
	const struct mailbox_update *update = sync_ctx->mbox->sync_hdr_update;

	if (update->uid_validity != 0) {
		sync_ctx->base_uid_validity = update->uid_validity;
		mail_ctx->imapbase_rewrite = TRUE;
		mail_ctx->need_rewrite = TRUE;
	}
	if (update->min_next_uid != 0 &&
	    sync_ctx->base_uid_last+1 < update->min_next_uid) {
		i_assert(sync_ctx->next_uid <= update->min_next_uid);
		sync_ctx->base_uid_last = update->min_next_uid-1;
		sync_ctx->next_uid = update->min_next_uid;
		mail_ctx->imapbase_rewrite = TRUE;
		mail_ctx->need_rewrite = TRUE;
	}
}

static bool mbox_sync_imapbase(struct mbox_sync_context *sync_ctx,
			       struct mbox_sync_mail_context *mail_ctx)
{
	if (sync_ctx->base_uid_validity != 0 &&
	    sync_ctx->hdr->uid_validity != 0 &&
	    sync_ctx->base_uid_validity != sync_ctx->hdr->uid_validity) {
		i_warning("UIDVALIDITY changed (%u -> %u) in mbox file %s",
			  sync_ctx->hdr->uid_validity,
			  sync_ctx->base_uid_validity,
			  mailbox_get_path(&sync_ctx->mbox->box));
		sync_ctx->index_reset = TRUE;
		return TRUE;
	}
	if (sync_ctx->mbox->sync_hdr_update != NULL)
		mbox_sync_hdr_update(sync_ctx, mail_ctx);
	return FALSE;
}

static int mbox_sync_loop(struct mbox_sync_context *sync_ctx,
                          struct mbox_sync_mail_context *mail_ctx,
			  bool partial)
{
	const struct mail_index_record *rec;
	uint32_t uid, messages_count;
	uoff_t offset;
	int ret;
	bool expunged, skipped_mails, uids_broken;

	messages_count =
		mail_index_view_get_messages_count(sync_ctx->sync_view);

	/* always start from first message so we can read X-IMAP or
	   X-IMAPbase header */
	ret = mbox_sync_seek_to_seq(sync_ctx, 0);
	if (ret <= 0)
		return ret;

	if (sync_ctx->renumber_uids) {
		/* expunge everything */
		while (sync_ctx->idx_seq <= messages_count) {
			mail_index_expunge(sync_ctx->t,
					   sync_ctx->idx_seq++);
		}
	}

	skipped_mails = uids_broken = FALSE;
	while ((ret = mbox_sync_read_next_mail(sync_ctx, mail_ctx)) > 0) {
		uid = mail_ctx->mail.uid;

		if (mail_ctx->seq == 1) {
			if (mbox_sync_imapbase(sync_ctx, mail_ctx)) {
				sync_ctx->mbox->mbox_hdr.dirty_flag = 1;
				return 0;
			}
		}

		if (mail_ctx->mail.uid_broken && partial) {
			/* UID ordering problems, resync everything to make
			   sure we get everything right */
			if (sync_ctx->mbox->mbox_hdr.dirty_flag != 0)
				return 0;

			mbox_sync_set_critical(sync_ctx,
				"UIDs broken with partial sync");

			sync_ctx->mbox->mbox_hdr.dirty_flag = 1;
			return 0;
		}
		if (mail_ctx->mail.uid_broken)
			uids_broken = TRUE;

		if (mail_ctx->mail.pseudo)
			uid = 0;

		rec = NULL; ret = 1;
		if (uid != 0) {
			if (!mbox_sync_read_index_rec(sync_ctx, uid, &rec))
				ret = 0;
		}

		if (ret == 0) {
			/* UID found but it's broken */
			uid = 0;
		} else if (uid == 0 &&
			   !mail_ctx->mail.pseudo &&
			   (sync_ctx->delay_writes ||
			    sync_ctx->idx_seq <= messages_count)) {
			/* If we can't use/store X-UID header, use MD5 sum.
			   Also check for existing MD5 sums when we're actually
			   able to write X-UIDs. */
			sync_ctx->mbox->mbox_save_md5 = TRUE;

			mbox_sync_find_index_md5(sync_ctx,
						 mail_ctx->hdr_md5_sum, &rec);
			if (rec != NULL)
				uid = mail_ctx->mail.uid = rec->uid;
		}

		/* get all sync records related to this message. with pseudo
		   message just get the first sync record so we can jump to
		   it with partial seeking. */
		mbox_sync_read_index_syncs(sync_ctx,
					   mail_ctx->mail.pseudo ? 1 : uid,
					   &expunged);

		if (mail_ctx->mail.pseudo) {
			/* if it was set, it was for the next message */
			expunged = FALSE;
		} else {
			if (rec == NULL) {
				/* message wasn't found from index. we have to
				   read everything from now on, no skipping */
				partial = FALSE;
			}
		}

		if (uid == 0 && !mail_ctx->mail.pseudo) {
			/* missing/broken X-UID. all the rest of the mails
			   need new UIDs. */
			while (sync_ctx->idx_seq <= messages_count) {
				mail_index_expunge(sync_ctx->t,
						   sync_ctx->idx_seq++);
			}

			if (sync_ctx->next_uid == (uint32_t)-1) {
				/* oh no, we're out of UIDs. this shouldn't
				   happen normally, so just try to get it fixed
				   without crashing. */
				mailbox_set_critical(&sync_ctx->mbox->box,
					"Out of UIDs, renumbering them in mbox");
				sync_ctx->renumber_uids = TRUE;
				return 0;
			}

			mail_ctx->need_rewrite = TRUE;
			mail_ctx->mail.uid = sync_ctx->next_uid++;
		}
		sync_ctx->prev_msg_uid = mail_ctx->mail.uid;

		if (!mail_ctx->mail.pseudo)
			mail_ctx->mail.idx_seq = sync_ctx->idx_seq;

		if (!expunged) {
			if (!mail_ctx->mail.pseudo) T_BEGIN {
				mbox_sync_update_flags(mail_ctx, rec);
			} T_END;
			if (mbox_sync_handle_header(mail_ctx) < 0)
				return -1;
			sync_ctx->dest_first_mail = FALSE;
		} else {
			mbox_sync_handle_expunge(mail_ctx);
		}

		if (!mail_ctx->mail.pseudo) {
			if (!expunged) T_BEGIN {
				mbox_sync_update_index(mail_ctx, rec);
			} T_END;
			sync_ctx->idx_seq++;
		}

		if (istream_raw_mbox_next(sync_ctx->input,
					  mail_ctx->mail.body_size) < 0)
			return -1;
		offset = istream_raw_mbox_get_start_offset(sync_ctx->input);

		if (sync_ctx->need_space_seq != 0) {
			if (mbox_sync_handle_missing_space(mail_ctx) < 0)
				return -1;
			if (mbox_sync_seek(sync_ctx, offset) < 0)
				return -1;
		} else if (sync_ctx->expunged_space > 0) {
			if (!expunged) {
				/* move the body */
				mbox_sync_file_update_ext_modified(sync_ctx);
				if (mbox_move(sync_ctx,
					      mail_ctx->body_offset -
					      sync_ctx->expunged_space,
					      mail_ctx->body_offset,
					      mail_ctx->mail.body_size) < 0)
					return -1;
				if (mbox_sync_seek(sync_ctx, offset) < 0)
					return -1;
			}
		} else if (partial) {
			ret = mbox_sync_partial_seek_next(sync_ctx, uid + 1,
							  &partial,
							  &skipped_mails);
			if (ret <= 0)
				break;
		}
	}
	if (ret < 0)
		return -1;

	if (istream_raw_mbox_is_eof(sync_ctx->input)) {
		/* rest of the messages in index don't exist -> expunge them */
		while (sync_ctx->idx_seq <= messages_count)
			mail_index_expunge(sync_ctx->t, sync_ctx->idx_seq++);
	}

	if (!skipped_mails)
		sync_ctx->mbox->mbox_hdr.dirty_flag = 0;
	sync_ctx->mbox->mbox_broken_offsets = FALSE;

	if (uids_broken && sync_ctx->delay_writes) {
		/* once we get around to writing the changes, we'll need to do
		   a full sync to avoid the "UIDs broken in partial sync"
		   error */
		sync_ctx->mbox->mbox_hdr.dirty_flag = 1;
	}
	return 1;
}

static int mbox_write_pseudo(struct mbox_sync_context *sync_ctx, bool force)
{
	string_t *str;
	unsigned int uid_validity;

	i_assert(sync_ctx->write_fd != -1);

	if (sync_ctx->mbox->sync_hdr_update != NULL) {
		const struct mailbox_update *update =
			sync_ctx->mbox->sync_hdr_update;
		bool change = FALSE;

		if (update->uid_validity != 0) {
			sync_ctx->base_uid_validity = update->uid_validity;
			change = TRUE;
		}
		if (update->min_next_uid != 0) {
			sync_ctx->base_uid_last = update->min_next_uid-1;
			change = TRUE;
		}
		if (!change && !force)
			return 0;
	}

	uid_validity = sync_ctx->base_uid_validity != 0 ?
		sync_ctx->base_uid_validity : sync_ctx->hdr->uid_validity;
	i_assert(uid_validity != 0);

	str = t_str_new(1024);
	str_printfa(str, "%sDate: %s\n"
		    "From: Mail System Internal Data <MAILER-DAEMON@%s>\n"
		    "Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"
		    "\nMessage-ID: <%s@%s>\n"
		    "X-IMAP: %u %010u\n"
		    "Status: RO\n"
		    "\n"
		    PSEUDO_MESSAGE_BODY
		    "\n",
                    mbox_from_create("MAILER_DAEMON", ioloop_time),
		    message_date_create(ioloop_time),
		    my_hostname, dec2str(ioloop_time), my_hostname,
		    uid_validity, sync_ctx->next_uid-1);

	if (pwrite_full(sync_ctx->write_fd,
			str_data(str), str_len(str), 0) < 0) {
		if (!ENOSPACE(errno)) {
			mbox_set_syscall_error(sync_ctx->mbox,
					       "pwrite_full()");
			return -1;
		}

		/* out of disk space, truncate to empty */
		if (ftruncate(sync_ctx->write_fd, 0) < 0)
			mbox_set_syscall_error(sync_ctx->mbox, "ftruncate()");
	}

	sync_ctx->base_uid_validity = uid_validity;
	sync_ctx->base_uid_last_offset = 0; /* don't bother calculating */
	sync_ctx->base_uid_last = sync_ctx->next_uid-1;
	return 0;
}

static int mbox_append_zero(struct mbox_sync_context *sync_ctx,
			    uoff_t orig_file_size, uoff_t count)
{
	char block[IO_BLOCK_SIZE];
	uoff_t offset = orig_file_size;
	ssize_t ret = 0;

	memset(block, 0, I_MIN(sizeof(block), count));
	while (count > 0) {
		ret = pwrite(sync_ctx->write_fd, block,
			     I_MIN(sizeof(block), count), offset);
		if (ret < 0)
			break;
		offset += ret;
		count -= ret;
	}

	if (ret < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pwrite()");
		if (ftruncate(sync_ctx->write_fd, orig_file_size) < 0)
			mbox_set_syscall_error(sync_ctx->mbox, "ftruncate()");
		return -1;
	}
	return 0;
}

static int mbox_sync_handle_eof_updates(struct mbox_sync_context *sync_ctx,
					struct mbox_sync_mail_context *mail_ctx)
{
	uoff_t file_size, offset, padding, trailer_size;
	int ret;

	if (!istream_raw_mbox_is_eof(sync_ctx->input)) {
		i_assert(sync_ctx->need_space_seq == 0);
		i_assert(sync_ctx->expunged_space == 0);
		return 0;
	}

	ret = i_stream_get_size(sync_ctx->file_input, TRUE, &file_size);
	if (ret < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "i_stream_get_size()");
		return -1;
	}
	if (ret == 0) {
		/* Not a file - allow anyway */
		return 0;
	}

	if (file_size < sync_ctx->file_input->v_offset) {
		mbox_sync_set_critical(sync_ctx,
			"file size unexpectedly shrank "
			"(%"PRIuUOFF_T" vs %"PRIuUOFF_T")", file_size,
			sync_ctx->file_input->v_offset);
		return -1;
	}
	trailer_size = file_size - sync_ctx->file_input->v_offset;
	i_assert(trailer_size <= 2);

	if (sync_ctx->need_space_seq != 0) {
		i_assert(sync_ctx->write_fd != -1);

		i_assert(sync_ctx->space_diff < 0);
		padding = MBOX_HEADER_PADDING *
			(sync_ctx->seq - sync_ctx->need_space_seq + 1);
		sync_ctx->space_diff -= padding;

		i_assert(sync_ctx->expunged_space <= -sync_ctx->space_diff);
		sync_ctx->space_diff += sync_ctx->expunged_space;
		sync_ctx->expunged_space = 0;

		if (mail_ctx->have_eoh && !mail_ctx->updated)
			str_append_c(mail_ctx->header, '\n');

		i_assert(sync_ctx->space_diff < 0);

		if (mbox_append_zero(sync_ctx, file_size,
				     -sync_ctx->space_diff) < 0)
			return -1;
		mbox_sync_file_updated(sync_ctx, FALSE);

		if (mbox_sync_rewrite(sync_ctx, mail_ctx, file_size,
				      -sync_ctx->space_diff, padding,
				      sync_ctx->need_space_seq,
				      sync_ctx->seq) < 0)
			return -1;

		update_from_offsets(sync_ctx);

		sync_ctx->need_space_seq = 0;
		array_clear(&sync_ctx->mails);
		p_clear(sync_ctx->saved_keywords_pool);
	}

	if (sync_ctx->expunged_space > 0) {
		i_assert(sync_ctx->write_fd != -1);

		mbox_sync_file_update_ext_modified(sync_ctx);

		/* copy trailer, then truncate the file */
		file_size = sync_ctx->last_stat.st_size;
		if (file_size == (uoff_t)sync_ctx->expunged_space) {
			/* everything deleted, the trailer_size still contains
			   the \n trailer though */
			trailer_size = 0;
		} else if (sync_ctx->expunged_space == (off_t)file_size + 1 ||
			   sync_ctx->expunged_space == (off_t)file_size + 2) {
			/* everything deleted and we didn't have a proper
			   trailer. */
			trailer_size = 0;
			sync_ctx->expunged_space = file_size;
		}

		i_assert(file_size >= sync_ctx->expunged_space + trailer_size);
		offset = file_size - sync_ctx->expunged_space - trailer_size;
		i_assert(offset == 0 || offset > 31);

		if (mbox_move(sync_ctx, offset,
			      offset + sync_ctx->expunged_space,
			      trailer_size) < 0)
			return -1;
		if (ftruncate(sync_ctx->write_fd,
			      offset + trailer_size) < 0) {
			mbox_set_syscall_error(sync_ctx->mbox, "ftruncate()");
			return -1;
		}

		if (offset == 0) {
			if (mbox_write_pseudo(sync_ctx, TRUE) < 0)
				return -1;
		}

                sync_ctx->expunged_space = 0;
		mbox_sync_file_updated(sync_ctx, FALSE);
	} else {
		if (file_size == 0 && sync_ctx->mbox->sync_hdr_update != NULL) {
			if (mbox_write_pseudo(sync_ctx, FALSE) < 0)
				return -1;
		}
	}
	return 0;
}

static void
mbox_sync_index_update_ext_header(struct mbox_mailbox *mbox,
				  struct mail_index_transaction *trans)
{
	const struct mailbox_update *update = mbox->sync_hdr_update;
	const void *data;
	size_t data_size;

	if (update != NULL && !guid_128_is_empty(update->mailbox_guid)) {
		memcpy(mbox->mbox_hdr.mailbox_guid, update->mailbox_guid,
		       sizeof(mbox->mbox_hdr.mailbox_guid));
	} else if (guid_128_is_empty(mbox->mbox_hdr.mailbox_guid)) {
		guid_128_generate(mbox->mbox_hdr.mailbox_guid);
	}

	mail_index_get_header_ext(mbox->box.view, mbox->mbox_ext_idx,
				  &data, &data_size);
	if (data_size != sizeof(mbox->mbox_hdr) ||
	    memcmp(data, &mbox->mbox_hdr, data_size) != 0) {
		if (data_size != sizeof(mbox->mbox_hdr)) {
			/* upgrading from v1.x */
			mail_index_ext_resize(trans, mbox->mbox_ext_idx,
					      sizeof(mbox->mbox_hdr),
					      sizeof(uint64_t),
					      sizeof(uint64_t));
		}
		mail_index_update_header_ext(trans, mbox->mbox_ext_idx,
					     0, &mbox->mbox_hdr,
					     sizeof(mbox->mbox_hdr));
	}
}

static uint32_t mbox_get_uidvalidity_next(struct mailbox_list *list)
{
	const char *path;

	path = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"MBOX_UIDVALIDITY_FNAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

static int mbox_sync_update_index_header(struct mbox_sync_context *sync_ctx)
{
	struct mail_index_view *view;
	const struct stat *st;
	uint32_t first_recent_uid, seq, seq2;

	if (i_stream_stat(sync_ctx->file_input, FALSE, &st) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "i_stream_stat()");
		return -1;
	}

	if (sync_ctx->moved_offsets &&
	    ((uint64_t)st->st_size == sync_ctx->mbox->mbox_hdr.sync_size ||
	     (uint64_t)st->st_size == sync_ctx->orig_size)) {
		/* We moved messages inside the mbox file without changing
		   the file's size. If mtime doesn't change, another process
		   not using the same index file as us can't know that the file
		   was changed. So make sure the mtime changes. This should
		   happen rarely enough that the sleeping doesn't become a
		   performance problem.

		   Note that to do this perfectly safe we should do this wait
		   whenever mails are moved or expunged, regardless of whether
		   the file's size changed. That however could become a
		   performance problem and the consequences of being wrong are
		   quite minimal (an extra logged error message). */
		while (sync_ctx->orig_mtime == st->st_mtime) {
			usleep(500000);
			if (utime(mailbox_get_path(&sync_ctx->mbox->box), NULL) < 0) {
				mbox_set_syscall_error(sync_ctx->mbox,
						       "utime()");
				return -1;
			}

			if (i_stream_stat(sync_ctx->file_input, FALSE, &st) < 0) {
				mbox_set_syscall_error(sync_ctx->mbox,
						       "i_stream_stat()");
				return -1;
			}
		}
	}

	sync_ctx->mbox->mbox_hdr.sync_mtime = st->st_mtime;
	sync_ctx->mbox->mbox_hdr.sync_size = st->st_size;
	mbox_sync_index_update_ext_header(sync_ctx->mbox, sync_ctx->t);

	/* only reason not to have UID validity at this point is if the file
	   is entirely empty. In that case just make up a new one if needed. */
	i_assert(sync_ctx->base_uid_validity != 0 || st->st_size <= 0);

	if (sync_ctx->base_uid_validity == 0) {
		sync_ctx->base_uid_validity = sync_ctx->hdr->uid_validity != 0 ?
			sync_ctx->hdr->uid_validity :
			mbox_get_uidvalidity_next(sync_ctx->mbox->box.list);
	}
	if (sync_ctx->base_uid_validity != sync_ctx->hdr->uid_validity) {
		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, uid_validity),
			&sync_ctx->base_uid_validity,
			sizeof(sync_ctx->base_uid_validity), TRUE);
	}

	if (istream_raw_mbox_is_eof(sync_ctx->input) &&
	    sync_ctx->next_uid != sync_ctx->hdr->next_uid) {
		i_assert(sync_ctx->next_uid != 0);
		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, next_uid),
			&sync_ctx->next_uid, sizeof(sync_ctx->next_uid), FALSE);
	}

	if (sync_ctx->last_nonrecent_uid < sync_ctx->hdr->first_recent_uid) {
		/* other sessions have already marked more messages as
		   recent. */
		sync_ctx->last_nonrecent_uid =
			sync_ctx->hdr->first_recent_uid - 1;
	}

	/* mark recent messages */
	view = mail_index_transaction_open_updated_view(sync_ctx->t);
	if (mail_index_lookup_seq_range(view, sync_ctx->last_nonrecent_uid + 1,
					(uint32_t)-1, &seq, &seq2)) {
		mailbox_recent_flags_set_seqs(&sync_ctx->mbox->box,
					      view, seq, seq2);
	}
	mail_index_view_close(&view);

	first_recent_uid = !sync_ctx->keep_recent ?
		sync_ctx->next_uid : sync_ctx->last_nonrecent_uid + 1;
	if (sync_ctx->hdr->first_recent_uid < first_recent_uid) {
		mail_index_update_header(sync_ctx->t,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	return 0;
}

static void mbox_sync_restart(struct mbox_sync_context *sync_ctx)
{
	sync_ctx->base_uid_validity = 0;
	sync_ctx->base_uid_last = 0;
	sync_ctx->base_uid_last_offset = 0;

	array_clear(&sync_ctx->mails);
	p_clear(sync_ctx->saved_keywords_pool);

	index_sync_changes_reset(sync_ctx->sync_changes);
        mail_index_sync_reset(sync_ctx->index_sync_ctx);
	mail_index_transaction_reset(sync_ctx->t);

	if (sync_ctx->index_reset) {
		mail_index_reset(sync_ctx->t);
		sync_ctx->reset_hdr.next_uid = 1;
		sync_ctx->hdr = &sync_ctx->reset_hdr;
		mailbox_recent_flags_reset(&sync_ctx->mbox->box);
	}

	sync_ctx->prev_msg_uid = 0;
	sync_ctx->next_uid = sync_ctx->hdr->next_uid;
	sync_ctx->idx_next_uid = sync_ctx->hdr->next_uid;
	sync_ctx->seq = 0;
	sync_ctx->idx_seq = 1;
	sync_ctx->need_space_seq = 0;
	sync_ctx->expunged_space = 0;
	sync_ctx->space_diff = 0;

	sync_ctx->dest_first_mail = TRUE;
	sync_ctx->ext_modified = FALSE;
	sync_ctx->errors = FALSE;
}

static int mbox_sync_do(struct mbox_sync_context *sync_ctx,
			enum mbox_sync_flags flags)
{
	struct mbox_index_header *mbox_hdr = &sync_ctx->mbox->mbox_hdr;
	struct mbox_sync_mail_context mail_ctx;
	const struct stat *st;
	unsigned int i;
	bool partial;
	int ret;

	if (i_stream_stat(sync_ctx->file_input, FALSE, &st) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "i_stream_stat()");
		return -1;
	}
	sync_ctx->last_stat = *st;
	sync_ctx->orig_size = st->st_size;
	sync_ctx->orig_atime = st->st_atime;
	sync_ctx->orig_mtime = st->st_mtime;

	if ((flags & MBOX_SYNC_FORCE_SYNC) != 0) {
		/* forcing a full sync. assume file has changed. */
		partial = FALSE;
		mbox_hdr->dirty_flag = 1;
	} else if ((uint32_t)st->st_mtime == mbox_hdr->sync_mtime &&
		   (uint64_t)st->st_size == mbox_hdr->sync_size) {
		/* file is fully synced */
		if (mbox_hdr->dirty_flag != 0 && (flags & MBOX_SYNC_UNDIRTY) != 0)
			partial = FALSE;
		else
			partial = TRUE;
	} else if ((flags & MBOX_SYNC_UNDIRTY) != 0 ||
		   (uint64_t)st->st_size == mbox_hdr->sync_size) {
		/* we want to do full syncing. always do this if
		   file size hasn't changed but timestamp has. it most
		   likely means that someone had modified some header
		   and we probably want to know about it */
		partial = FALSE;
		sync_ctx->mbox->mbox_hdr.dirty_flag = 1;
	} else {
		/* see if we can delay syncing the whole file.
		   normally we only notice expunges and appends
		   in partial syncing. */
		partial = TRUE;
		sync_ctx->mbox->mbox_hdr.dirty_flag = 1;
	}

	mbox_sync_restart(sync_ctx);
	for (i = 0;;) {
		ret = mbox_sync_loop(sync_ctx, &mail_ctx, partial);
		if (ret > 0 && !sync_ctx->errors)
			break;
		if (ret < 0)
			return -1;

		/* a) partial sync didn't work
		   b) we ran out of UIDs
		   c) syncing had errors */
		if (sync_ctx->delay_writes &&
		    (sync_ctx->errors || sync_ctx->renumber_uids)) {
			/* fixing a broken mbox state, be sure to write
			   the changes (except if we're readonly). */
			if (!sync_ctx->readonly)
				sync_ctx->delay_writes = FALSE;
		}
		if (++i == 3)
			break;

		mbox_sync_restart(sync_ctx);
		partial = FALSE;
	}

	if (mbox_sync_handle_eof_updates(sync_ctx, &mail_ctx) < 0)
		return -1;

	/* only syncs left should be just appends (and their updates)
	   which weren't synced yet for some reason (crash). we'll just
	   ignore them, as we've overwritten them above. */
	index_sync_changes_reset(sync_ctx->sync_changes);

	if (sync_ctx->base_uid_last != sync_ctx->next_uid-1 &&
	    ret > 0 && !sync_ctx->delay_writes &&
	    sync_ctx->base_uid_last_offset != 0) {
		/* Rewrite uid_last in X-IMAPbase header if we've seen it
		   (ie. the file isn't empty) */
                ret = mbox_rewrite_base_uid_last(sync_ctx);
	} else {
		ret = 0;
	}

	if (mbox_sync_update_index_header(sync_ctx) < 0)
		return -1;
	return ret;
}

int mbox_sync_header_refresh(struct mbox_mailbox *mbox)
{
	const void *data;
	size_t data_size;

	if (mail_index_refresh(mbox->box.index) < 0) {
		mailbox_set_index_error(&mbox->box);
		return -1;
	}

	mail_index_get_header_ext(mbox->box.view, mbox->mbox_ext_idx,
				  &data, &data_size);
	if (data_size == 0) {
		/* doesn't exist yet. */
		i_zero(&mbox->mbox_hdr);
		return 0;
	}

	memcpy(&mbox->mbox_hdr, data, I_MIN(sizeof(mbox->mbox_hdr), data_size));
	if (mbox->mbox_broken_offsets)
		mbox->mbox_hdr.dirty_flag = 1;
	return 0;
}

int mbox_sync_get_guid(struct mbox_mailbox *mbox)
{
	struct mail_index_transaction *trans;
	unsigned int lock_id;
	int ret;

	if (mbox_lock(mbox, F_WRLCK, &lock_id) <= 0)
		return -1;

	ret = mbox_sync_header_refresh(mbox);
	if (ret == 0) {
		trans = mail_index_transaction_begin(mbox->box.view,
				MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
		mbox_sync_index_update_ext_header(mbox, trans);
		ret = mail_index_transaction_commit(&trans);
	}
	mbox_unlock(mbox, lock_id);
	return ret;
}

int mbox_sync_has_changed(struct mbox_mailbox *mbox, bool leave_dirty)
{
	const struct stat *st;
	struct stat statbuf;

	if (mbox->mbox_file_stream != NULL && mbox->mbox_fd == -1) {
		/* read-only stream */
		if (i_stream_stat(mbox->mbox_file_stream, FALSE, &st) < 0) {
			if (errno == ENOENT) {
				mailbox_set_deleted(&mbox->box);
				return 0;
			}
			mbox_set_syscall_error(mbox, "i_stream_stat()");
			return -1;
		}
	} else {
		if (stat(mailbox_get_path(&mbox->box), &statbuf) < 0) {
			if (errno == ENOENT) {
				mailbox_set_deleted(&mbox->box);
				return 0;
			}
			mbox_set_syscall_error(mbox, "stat()");
			return -1;
		}
		st = &statbuf;
	}

	if (mbox_sync_header_refresh(mbox) < 0)
		return -1;

	if (guid_128_is_empty(mbox->mbox_hdr.mailbox_guid)) {
		/* need to assign mailbox GUID */
		return 1;
	}

	if ((uint32_t)st->st_mtime == mbox->mbox_hdr.sync_mtime &&
	    (uint64_t)st->st_size == mbox->mbox_hdr.sync_size) {
		/* fully synced */
		if (mbox->mbox_hdr.dirty_flag != 0 || leave_dirty)
			return 0;
		/* flushing dirtiness */
	}

	/* file changed */
	return 1;
}

static void mbox_sync_context_free(struct mbox_sync_context *sync_ctx)
{
	index_sync_changes_deinit(&sync_ctx->sync_changes);
	index_storage_expunging_deinit(&sync_ctx->mbox->box);
	if (sync_ctx->index_sync_ctx != NULL)
		mail_index_sync_rollback(&sync_ctx->index_sync_ctx);
	pool_unref(&sync_ctx->mail_keyword_pool);
	pool_unref(&sync_ctx->saved_keywords_pool);
	str_free(&sync_ctx->header);
	str_free(&sync_ctx->from_line);
	array_free(&sync_ctx->mails);
}

static int mbox_sync_int(struct mbox_mailbox *mbox, enum mbox_sync_flags flags,
			 unsigned int *lock_id)
{
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	struct mbox_sync_context sync_ctx;
	enum mail_index_sync_flags sync_flags;
	int ret;
	bool changed, delay_writes, readonly;

	readonly = mbox_is_backend_readonly(mbox) ||
		(flags & MBOX_SYNC_READONLY) != 0;
	delay_writes = readonly ||
		((flags & MBOX_SYNC_REWRITE) == 0 &&
		 mbox->storage->set->mbox_lazy_writes);

	if (!mbox->storage->set->mbox_dirty_syncs &&
	    !mbox->storage->set->mbox_very_dirty_syncs)
		flags |= MBOX_SYNC_UNDIRTY;

	if ((flags & MBOX_SYNC_LOCK_READING) != 0) {
		if (mbox_lock(mbox, F_RDLCK, lock_id) <= 0)
			return -1;
	}

	if ((flags & MBOX_SYNC_HEADER) != 0 ||
	    (flags & MBOX_SYNC_FORCE_SYNC) != 0) {
		if (mbox_sync_header_refresh(mbox) < 0)
			return -1;
		changed = TRUE;
	} else {
		bool leave_dirty = (flags & MBOX_SYNC_UNDIRTY) == 0;
		if ((ret = mbox_sync_has_changed(mbox, leave_dirty)) < 0)
			return -1;
		changed = ret > 0;
	}

	if ((flags & MBOX_SYNC_LOCK_READING) != 0) {
		/* we just want to lock it for reading. if mbox hasn't been
		   modified don't do any syncing. */
		if (!changed)
			return 0;

		/* have to sync to make sure offsets have stayed the same */
		mbox_unlock(mbox, *lock_id);
		*lock_id = 0;
	}

	/* flush input streams' buffers */
	if (mbox->mbox_stream != NULL)
		i_stream_sync(mbox->mbox_stream);
	if (mbox->mbox_file_stream != NULL)
		i_stream_sync(mbox->mbox_file_stream);

again:
	if (changed) {
		/* we're most likely modifying the mbox while syncing, just
		   lock it for writing immediately. the mbox must be locked
		   before index syncing is started to avoid deadlocks, so we
		   don't have much choice either (well, easy ones anyway). */
		int lock_type = readonly ? F_RDLCK : F_WRLCK;

		if ((ret = mbox_lock(mbox, lock_type, lock_id)) <= 0) {
			if (ret == 0 || lock_type == F_RDLCK)
				return -1;

			/* try as read-only */
			if (mbox_lock(mbox, F_RDLCK, lock_id) <= 0)
				return -1;
			mbox->backend_readonly = readonly = TRUE;
			mbox->backend_readonly_set = TRUE;
			delay_writes = TRUE;
		}
	}

	sync_flags = index_storage_get_sync_flags(&mbox->box);
	if ((flags & MBOX_SYNC_REWRITE) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY;

	ret = index_storage_expunged_sync_begin(&mbox->box, &index_sync_ctx,
						&sync_view, &trans, sync_flags);
	if (ret <= 0)
		return ret;

	if ((mbox->box.flags & MAILBOX_FLAG_DROP_RECENT) != 0) {
		/* see if we need to drop recent flags */
		sync_ctx.hdr = mail_index_get_header(sync_view);
		if (sync_ctx.hdr->first_recent_uid < sync_ctx.hdr->next_uid)
			changed = TRUE;
	}

	if (!changed && !mail_index_sync_have_more(index_sync_ctx)) {
		/* nothing to do */
	nothing_to_do:
		/* index may need to do internal syncing though, so commit
		   instead of rolling back. */
		index_storage_expunging_deinit(&mbox->box);
		if (mail_index_sync_commit(&index_sync_ctx) < 0) {
			mailbox_set_index_error(&mbox->box);
			return -1;
		}
		return 0;
	}

	i_zero(&sync_ctx);
	sync_ctx.mbox = mbox;
	sync_ctx.keep_recent =
		(mbox->box.flags & MAILBOX_FLAG_DROP_RECENT) == 0;

	sync_ctx.hdr = mail_index_get_header(sync_view);
	sync_ctx.from_line = str_new(default_pool, 256);
	sync_ctx.header = str_new(default_pool, 4096);

	sync_ctx.index_sync_ctx = index_sync_ctx;
	sync_ctx.sync_view = sync_view;
	sync_ctx.t = trans;
	sync_ctx.mail_keyword_pool =
		pool_alloconly_create("mbox keywords", 512);
	sync_ctx.saved_keywords_pool =
		pool_alloconly_create("mbox saved keywords", 4096);

	/* make sure we've read the latest keywords in index */
	(void)mail_index_get_keywords(mbox->box.index);

	i_array_init(&sync_ctx.mails, 64);

	sync_ctx.flags = flags;
	sync_ctx.readonly = readonly;
	sync_ctx.delay_writes = delay_writes;

	sync_ctx.sync_changes =
		index_sync_changes_init(index_sync_ctx, sync_view, trans,
					sync_ctx.delay_writes);

	if (!changed && delay_writes) {
		/* if we have only flag changes, we don't need to open the
		   mbox file */
		bool expunged;
		uint32_t uid;

		mbox_sync_read_index_syncs(&sync_ctx, 1, &expunged);
		uid = expunged ? 1 :
			index_sync_changes_get_next_uid(sync_ctx.sync_changes);
		if (uid == 0) {
			sync_ctx.index_sync_ctx = NULL;
			mbox_sync_context_free(&sync_ctx);
			goto nothing_to_do;
		}
	}

	if (*lock_id == 0) {
		/* ok, we have something to do but no locks. we'll have to
		   restart syncing to avoid deadlocking. */
		mbox_sync_context_free(&sync_ctx);
		changed = TRUE;
		goto again;
	}

	if (mbox_file_open_stream(mbox) < 0) {
		mbox_sync_context_free(&sync_ctx);
		return -1;
	}

	sync_ctx.file_input = sync_ctx.mbox->mbox_file_stream;
	sync_ctx.input = sync_ctx.mbox->mbox_stream;
	sync_ctx.write_fd = sync_ctx.mbox->mbox_lock_type != F_WRLCK ? -1 :
		sync_ctx.mbox->mbox_fd;

	ret = mbox_sync_do(&sync_ctx, flags);

	if (ret < 0)
		mail_index_sync_rollback(&index_sync_ctx);
	else if (mail_index_sync_commit(&index_sync_ctx) < 0) {
		mailbox_set_index_error(&mbox->box);
		ret = -1;
	}
	sync_ctx.t = NULL;
	sync_ctx.index_sync_ctx = NULL;

	if (ret == 0 && mbox->mbox_fd != -1 && sync_ctx.keep_recent &&
	    !readonly) {
		/* try to set atime back to its original value.
		   (it'll fail with EPERM for shared mailboxes where we aren't
		   the file's owner) */
		struct utimbuf buf;
		struct stat st;

		if (fstat(mbox->mbox_fd, &st) < 0)
			mbox_set_syscall_error(mbox, "fstat()");
		else {
			buf.modtime = st.st_mtime;
			buf.actime = sync_ctx.orig_atime;
			if (utime(mailbox_get_path(&mbox->box), &buf) < 0 &&
			    errno != EPERM)
				mbox_set_syscall_error(mbox, "utime()");
		}
	}

	i_assert(*lock_id != 0);

	if (mbox->storage->storage.set->mail_nfs_storage &&
	    mbox->mbox_fd != -1) {
		if (fdatasync(mbox->mbox_fd) < 0) {
			mbox_set_syscall_error(mbox, "fdatasync()");
			ret = -1;
		}
	}

	mbox_sync_context_free(&sync_ctx);
	return ret;
}

int mbox_sync(struct mbox_mailbox *mbox, enum mbox_sync_flags flags)
{
	unsigned int lock_id = 0;
	int ret;

	i_assert(mbox->mbox_lock_type != F_RDLCK ||
		 (flags & MBOX_SYNC_READONLY) != 0);

	mbox->syncing = TRUE;
	ret = mbox_sync_int(mbox, flags, &lock_id);
	mbox->syncing = FALSE;

	if (lock_id != 0) {
		if (ret < 0) {
			/* syncing failed, don't leave it locked */
			mbox_unlock(mbox, lock_id);
		} else if ((flags & MBOX_SYNC_LOCK_READING) == 0) {
			if (mbox_unlock(mbox, lock_id) < 0)
				ret = -1;
		} else if (mbox->mbox_lock_type != F_RDLCK) {
			/* drop to read lock */
			unsigned int read_lock_id = 0;

			if (mbox_lock(mbox, F_RDLCK, &read_lock_id) <= 0)
				ret = -1;
			if (mbox_unlock(mbox, lock_id) < 0)
				ret = -1;
		}
	}

	if (mbox->box.v.sync_notify != NULL)
		mbox->box.v.sync_notify(&mbox->box, 0, 0);
	return ret;
}

struct mailbox_sync_context *
mbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mbox_mailbox *mbox = MBOX_MAILBOX(box);
	enum mbox_sync_flags mbox_sync_flags = 0;
	int ret = 0;

	if (index_mailbox_want_full_sync(&mbox->box, flags)) {
		if ((flags & MAILBOX_SYNC_FLAG_FULL_READ) != 0 &&
		    !mbox->storage->set->mbox_very_dirty_syncs)
			mbox_sync_flags |= MBOX_SYNC_UNDIRTY;
		if ((flags & MAILBOX_SYNC_FLAG_FULL_WRITE) != 0)
			mbox_sync_flags |= MBOX_SYNC_REWRITE;
		if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0) {
			mbox_sync_flags |= MBOX_SYNC_UNDIRTY |
				MBOX_SYNC_REWRITE | MBOX_SYNC_FORCE_SYNC;
		}

		ret = mbox_sync(mbox, mbox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
