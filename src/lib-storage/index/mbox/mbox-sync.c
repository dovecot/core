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

static int mbox_sync_grow_file(struct mbox_sync_context *sync_ctx,
			       struct mbox_sync_mail_context *mail_ctx,
			       uoff_t grow_size)
{
	uoff_t src_offset, file_size;

	i_assert(grow_size > 0);

	/* put the extra space between last message's header and body */
	file_size = i_stream_get_size(sync_ctx->file_input) + grow_size;
	if (file_set_size(sync_ctx->fd, file_size) < 0)
		return -1;

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

static void
mbox_sync_next_mail(struct mbox_sync_context *sync_ctx,
		    struct mbox_sync_mail_context *mail_ctx, uint32_t seq)
{
	uoff_t from_offset;

	memset(mail_ctx, 0, sizeof(*mail_ctx));
	mail_ctx->sync_ctx = sync_ctx;
	mail_ctx->seq = seq;
	mail_ctx->header = sync_ctx->header;

	mail_ctx->from_offset =
		istream_raw_mbox_get_start_offset(sync_ctx->input);
	mail_ctx->mail.offset =
		istream_raw_mbox_get_header_offset(sync_ctx->input);

	if (seq > 1 && sync_ctx->first_uid == mail_ctx->mail.uid) {
		/* First message was expunged and this is the next one.
		   Skip \n header */
		mail_ctx->from_offset++;
	}

	mbox_sync_parse_next_mail(sync_ctx->input, mail_ctx, FALSE);
	i_assert(sync_ctx->input->v_offset != mail_ctx->from_offset);

	mail_ctx->mail.body_size =
		istream_raw_mbox_get_body_size(sync_ctx->input,
					       mail_ctx->content_length);

	/* save the offset permanently with recent flag state */
	from_offset = (mail_ctx->from_offset - sync_ctx->expunged_space) << 1;
	if ((mail_ctx->mail.flags & MBOX_NONRECENT) == 0) {
		/* need to add 'O' flag to Status-header */
		mail_ctx->need_rewrite = TRUE;
		from_offset |= 1;
	}
	buffer_append(sync_ctx->ibox->mbox_data_buf, &from_offset,
		      sizeof(from_offset));
}

static void mbox_sync_apply_index_syncs(buffer_t *syncs_buf, uint8_t *flags,
					keywords_mask_t keywords)
{
	const struct mail_index_sync_rec *sync;
	size_t size, i;

	sync = buffer_get_data(syncs_buf, &size);
	size /= sizeof(*sync);

	for (i = 0; i < size; i++)
		mail_index_sync_flags_apply(&sync[i], flags, keywords);
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

	if (move_diff == 0)
		return 0;

	if (pwrite_full(ctx->sync_ctx->fd, str_data(str), str_len(str),
			ctx->from_offset + move_diff) < 0) {
		// FIXME: error handling
		return -1;
	}

	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 0;
}

static int mbox_sync_do(struct index_mailbox *ibox,
			struct mail_index_sync_ctx *index_sync_ctx,
			struct mail_index_view *sync_view,
			buffer_t *syncs, struct mail_index_sync_rec *sync_rec)
{
	struct mbox_sync_context sync_ctx;
	struct mbox_sync_mail_context mail_ctx;
	struct mail_index_transaction *t;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;
	struct istream *input;
	uint32_t seq, need_space_seq, idx_seq, messages_count;
	uint8_t new_flags;
	off_t space_diff, move_diff;
	uoff_t offset, extra_space, trailer_size;
	buffer_t *mails;
	size_t size;
	struct stat st;
	int sync_expunge, ret = 0;

	t = mail_index_transaction_begin(sync_view, FALSE);

	if (ibox->mbox_data_buf == NULL) {
		ibox->mbox_data_buf =
			buffer_create_dynamic(default_pool, 512, (size_t)-1);
	} else {
		buffer_set_used_size(ibox->mbox_data_buf, 0);
	}

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.ibox = ibox;
	sync_ctx.file_input = ibox->mbox_file_stream;
	sync_ctx.input = ibox->mbox_stream;
	sync_ctx.fd = ibox->mbox_fd;
	sync_ctx.from_line = str_new(default_pool, 256);
	sync_ctx.header = str_new(default_pool, 4096);
	sync_ctx.next_uid = 1;

	input = sync_ctx.input;
	istream_raw_mbox_seek(input, 0);

	mails = buffer_create_dynamic(default_pool, 4096, (size_t)-1);

	messages_count = mail_index_view_get_message_count(sync_view);

	space_diff = 0; need_space_seq = 0; idx_seq = 0; rec = NULL;
	for (seq = 0;;) {
		/* set input->eof */
		(void)istream_raw_mbox_get_header_offset(input);
		if (input->eof)
			break;
		seq++;

		mbox_sync_next_mail(&sync_ctx, &mail_ctx, seq);

		/* get all sync records related to this message */
		ret = 1; sync_expunge = FALSE;
		mbox_sync_buffer_delete_old(syncs, mail_ctx.mail.uid);
		while (mail_ctx.mail.uid >= sync_rec->uid1 && ret > 0) {
			if (sync_rec->uid1 != 0) {
				i_assert(mail_ctx.mail.uid <= sync_rec->uid2);
				buffer_append(syncs, sync_rec,
					      sizeof(*sync_rec));

				if (sync_rec->type ==
				    MAIL_INDEX_SYNC_TYPE_EXPUNGE)
					sync_expunge = TRUE;
			}
			ret = mail_index_sync_next(index_sync_ctx, sync_rec);
			if (ret == 0)
				memset(sync_rec, 0, sizeof(*sync_rec));
		}
		if (ret < 0)
			break;

		if (seq == 1 && sync_ctx.base_uid_validity == 0) {
			if (mail_index_get_header(sync_view, &hdr) < 0) {
				ret = -1;
				break;
			}
			sync_ctx.base_uid_validity =
				hdr->uid_validity == 0 ? (uint32_t)ioloop_time :
				hdr->uid_validity;
		}

		if (!sync_expunge && sync_ctx.first_uid == 0)
			sync_ctx.first_uid = mail_ctx.mail.uid;

		if ((mail_ctx.need_rewrite || sync_ctx.expunged_space > 0 ||
		     buffer_get_used_size(syncs) != 0) && !ibox->readonly) {
			if (ibox->mbox_lock_type == F_RDLCK) {
				ret = -2;
				break;
			}

			if (sync_expunge) {
				ret = 1;
				mail_ctx.mail.offset = mail_ctx.from_offset;
				mail_ctx.mail.space =
					mail_ctx.body_offset -
					mail_ctx.from_offset +
					mail_ctx.mail.body_size;
				mail_ctx.mail.body_size = 0;

				if (seq == 1)
					mail_ctx.mail.space++;

				sync_ctx.expunged_space += mail_ctx.mail.space;
			} else {
				move_diff = need_space_seq != 0 ? 0 :
					-sync_ctx.expunged_space;

				/* read the From-line */
				if (move_diff != 0 &&
				    mbox_read_from_line(&mail_ctx) < 0) {
					ret = -1;
					break;
				}

				mbox_sync_update_header(&mail_ctx, syncs);
				ret = mbox_sync_try_rewrite(&mail_ctx,
							    move_diff);

				if (ret > 0) {
					mail_ctx.mail.offset += move_diff;
					ret = mbox_write_from_line(&mail_ctx,
								   move_diff);
					if (ret == 0)
						ret = 1;
				}

				if (ret < 0)
					break;
			}

			if (ret == 0 && need_space_seq == 0) {
				/* first mail with no space to write it */
				need_space_seq = seq;
				space_diff = 0;

				if (sync_ctx.expunged_space > 0) {
					/* create dummy message to describe
					   the expunged data */
					struct mbox_sync_mail mail;

					memset(&mail, 0, sizeof(mail));
					mail.offset = mail_ctx.from_offset -
						sync_ctx.expunged_space;
					mail.space = sync_ctx.expunged_space;

					need_space_seq--;
					buffer_append(mails, &mail,
						      sizeof(mail));
				}
			}
		}

		/* update index */
		do {
			if (rec != NULL && rec->uid >= mail_ctx.mail.uid)
				break;

			if (idx_seq >= messages_count) {
				rec = NULL;
				break;
			}

			if (rec != NULL)
				mail_index_expunge(t, idx_seq);

			ret = mail_index_lookup(sync_view, ++idx_seq, &rec);
		} while (ret == 0);

		if (ret < 0)
			break;
		if (rec != NULL && rec->uid != mail_ctx.mail.uid) {
			/* new UID in the middle of the mailbox -
			   shouldn't happen */
			mail_storage_set_critical(ibox->box.storage,
				"mbox sync: UID inserted in the middle "
				"of mailbox (%u > %u)",
				rec->uid, mail_ctx.mail.uid);
			mail_index_mark_corrupted(ibox->index);
			ret = -1;
			break;
		}

		if (sync_expunge) {
			if (rec != NULL)
				mail_index_expunge(t, idx_seq);
		} else if (rec != NULL) {
			/* see if flags changed */
			keywords_mask_t old_keywords;
			uint8_t old_flags;

			old_flags = rec->flags;
			memcpy(old_keywords, rec->keywords,
			       INDEX_KEYWORDS_BYTE_COUNT);
			mbox_sync_apply_index_syncs(syncs, &old_flags,
						    old_keywords);

			new_flags = (rec->flags & ~MAIL_FLAGS_MASK) |
				(mail_ctx.mail.flags &
				 (MAIL_FLAGS_MASK^MAIL_RECENT));

			if (old_flags != new_flags ||
			    memcmp(old_keywords, mail_ctx.mail.keywords,
				   INDEX_KEYWORDS_BYTE_COUNT) != 0) {
				mail_index_update_flags(t, idx_seq,
							MODIFY_REPLACE,
							new_flags,
							mail_ctx.mail.keywords);
			}

			/* we used this record */
			rec = NULL;
		} else {
			/* new message */
			mail_index_append(t, mail_ctx.mail.uid, &idx_seq);
			new_flags = mail_ctx.mail.flags &
				(MAIL_FLAGS_MASK^MAIL_RECENT);
			mail_index_update_flags(t, idx_seq, MODIFY_REPLACE,
						new_flags,
						mail_ctx.mail.keywords);
		}

		istream_raw_mbox_next(input, mail_ctx.mail.body_size);
		offset = istream_raw_mbox_get_start_offset(input);

		if (sync_ctx.expunged_space > 0 && !sync_expunge &&
		    need_space_seq == 0) {
			/* move the body */
			if (mbox_move(&sync_ctx,
				      mail_ctx.body_offset -
				      sync_ctx.expunged_space,
				      mail_ctx.body_offset,
				      mail_ctx.mail.body_size) < 0) {
				ret = -1;
				break;
			}
			i_stream_seek(input, offset);
		}

		if (need_space_seq != 0) {
			if (sync_expunge)
				mail_ctx.mail.uid = 0;

			buffer_append(mails, &mail_ctx.mail,
				      sizeof(mail_ctx.mail));

			space_diff += mail_ctx.mail.space;
			if (space_diff >= 0) {
				/* we have enough space now */
				extra_space = MBOX_HEADER_EXTRA_SPACE *
					(seq - need_space_seq + 1);
				if (sync_expunge &&
				    (size_t)space_diff > extra_space) {
					/* don't waste too much on extra
					   spacing */
					sync_ctx.expunged_space =
						space_diff - extra_space;
					space_diff = extra_space;
				} else {
					sync_ctx.expunged_space = 0;
				}
				if (mbox_sync_rewrite(&sync_ctx, mails,
						      need_space_seq, seq,
						      space_diff) < 0) {
					ret = -1;
					break;
				}
				/* mail_ctx may contain wrong data after
				   rewrite, so make sure we don't try to access
				   it */
				memset(&mail_ctx, 0, sizeof(mail_ctx));
				i_stream_seek(input, offset);

				need_space_seq = 0;
				buffer_set_used_size(mails, 0);
			}
		}
	}

	trailer_size = i_stream_get_size(sync_ctx.file_input) - offset;
	if (need_space_seq != 0 && ret >= 0) {
		i_assert(space_diff < 0);
		extra_space = MBOX_HEADER_EXTRA_SPACE *
			(seq - need_space_seq + 1);
		space_diff -= extra_space;

		space_diff += sync_ctx.expunged_space;
		sync_ctx.expunged_space -= -space_diff;

		if (mail_ctx.have_eoh && !mail_ctx.updated)
			str_append_c(mail_ctx.header, '\n');

		if (space_diff < 0 &&
		    mbox_sync_grow_file(&sync_ctx, &mail_ctx, -space_diff) < 0)
			ret = -1;
		else if (mbox_sync_try_rewrite(&mail_ctx, 0) < 0)
			ret = -1;
		else if (seq != need_space_seq) {
			buffer_set_used_size(mails, (seq-need_space_seq) *
					     sizeof(mail_ctx.mail));
			buffer_append(mails, &mail_ctx.mail,
				      sizeof(mail_ctx.mail));

			if (mbox_sync_rewrite(&sync_ctx, mails, need_space_seq,
					      seq, extra_space) < 0)
				ret = -1;
		}
	}

	if (sync_ctx.expunged_space > 0) {
		/* copy trailer, then truncate the file */
		offset = i_stream_get_size(sync_ctx.file_input) -
			sync_ctx.expunged_space - trailer_size;

		if (mbox_move(&sync_ctx, offset,
			      offset + sync_ctx.expunged_space,
			      trailer_size) < 0)
			ret = -1;
		else if (ftruncate(ibox->mbox_fd, offset + trailer_size) < 0)
			ret = -1;

		istream_raw_mbox_flush(input);
	}

	if (ret >= 0) {
		if (rec != NULL)
			mail_index_expunge(t, idx_seq);
		while (idx_seq < messages_count)
			mail_index_expunge(t, ++idx_seq);

		if (sync_ctx.base_uid_last+1 != sync_ctx.next_uid) {

			// FIXME: rewrite X-IMAPbase header
		}
	}

	if (ret >= 0) {
		/* only syncs left should be just appends (and their updates)
		   which weren't synced yet for some reason (crash). we'll just
		   ignore them, as we've overwritten them above. */
		while (mail_index_sync_next(index_sync_ctx, sync_rec) > 0)
			;
	}

	if (ret == 0) {
		if (fstat(ibox->mbox_fd, &st) < 0) {
			mbox_set_syscall_error(ibox, "fstat()");
			ret = -1;
		}
	}
	if (ret < 0) {
		st.st_mtime = 0;
		st.st_size = 0;
	}

	if (mail_index_get_header(sync_view, &hdr) < 0)
		ret = -1;

	if (sync_ctx.base_uid_validity != hdr->uid_validity) {
		mail_index_update_header(t,
			offsetof(struct mail_index_header, uid_validity),
			&sync_ctx.base_uid_validity,
			sizeof(sync_ctx.base_uid_validity));
	}
	if (sync_ctx.next_uid != hdr->next_uid) {
		mail_index_update_header(t,
			offsetof(struct mail_index_header, next_uid),
			&sync_ctx.next_uid, sizeof(sync_ctx.next_uid));
	}

	if ((uint32_t)st.st_mtime != hdr->sync_stamp) {
		uint32_t sync_stamp = st.st_mtime;

		mail_index_update_header(t,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp));
	}
	if ((uint64_t)st.st_mtime != hdr->sync_size) {
		uint64_t sync_size = st.st_size;

		mail_index_update_header(t,
			offsetof(struct mail_index_header, sync_size),
			&sync_size, sizeof(sync_size));
	}

	if (ret < 0)
		mail_index_transaction_rollback(t);
	else {
		if (mail_index_transaction_commit(t, &seq, &offset) < 0)
			ret = -1;
		else if (seq != 0) {
			ibox->commit_log_file_seq = seq;
			ibox->commit_log_file_offset = offset;
		}
	}

	if (ret != -2) {
		if (mail_index_sync_end(index_sync_ctx) < 0)
			ret = -1;
	}

	if (ret == 0) {
		ibox->commit_log_file_seq = 0;
		ibox->commit_log_file_offset = 0;
	} else {
		mail_storage_set_index_error(ibox);
	}

	ibox->mbox_data = buffer_get_data(ibox->mbox_data_buf, &size);
	ibox->mbox_data_count = size / sizeof(*ibox->mbox_data);

	str_free(sync_ctx.header);
	str_free(sync_ctx.from_line);
	buffer_free(mails);
	return ret < 0 ? ret : 0;
}

int mbox_sync(struct index_mailbox *ibox, int last_commit)
{
	struct mail_index_sync_ctx *index_sync_ctx;
        struct mail_index_view *sync_view;
	unsigned int lock_id;
	uint32_t seq;
	uoff_t offset;
	struct mail_index_sync_rec sync_rec;
	buffer_t *syncs;
	int ret, lock_type;

	if (last_commit) {
		seq = ibox->commit_log_file_seq;
		offset = ibox->commit_log_file_offset;
	} else {
		seq = (uint32_t)-1;
		offset = (uoff_t)-1;
	}

	ret = mail_index_sync_begin(ibox->index, &index_sync_ctx, &sync_view,
				    seq, offset);
	if (ret <= 0)
		return ret;

	memset(&sync_rec, 0, sizeof(sync_rec));
	syncs = buffer_create_dynamic(default_pool, 256, (size_t)-1);

	lock_type = mail_index_sync_have_more(index_sync_ctx) ?
		F_WRLCK : F_RDLCK;
	if (mbox_lock(ibox, lock_type, &lock_id) > 0 &&
	    mbox_file_open_stream(ibox) == 0) {
		ret = mbox_sync_do(ibox, index_sync_ctx, sync_view,
				   syncs, &sync_rec);
		if (ret == -2) {
			/* read lock -> write lock. do it again. */
			(void)mbox_unlock(ibox, lock_id);
			lock_id = 0;
			if (mbox_lock(ibox, F_WRLCK, &lock_id) <= 0)
				ret = -1;
			else if (mbox_file_open_stream(ibox) < 0)
				ret = -1;
			else {
				ret = mbox_sync_do(ibox, index_sync_ctx,
						   sync_view, syncs, &sync_rec);
			}
		}
	} else {
		(void)mail_index_sync_end(index_sync_ctx);
		ret = -1;
	}

	if (lock_id != 0) {
		if (mbox_unlock(ibox, lock_id) < 0)
			ret = -1;
	}

	buffer_free(syncs);
	return ret;
}

int mbox_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		ibox->sync_last_check = ioloop_time;

		if (mbox_sync(ibox, FALSE) < 0)
			return -1;
	}

	return index_storage_sync(box, flags);
}
