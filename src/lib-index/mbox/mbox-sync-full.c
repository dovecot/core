/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "hex-binary.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void skip_line(struct istream *input)
{
	const unsigned char *msg;
	size_t i, size;
	int ret;

	while ((ret = i_stream_read_data(input, &msg, &size, 0)) > 0) {
		for (i = 0; i < size; i++) {
			if (msg[i] == '\n') {
				i_stream_skip(input, i+1);
				return;
			}
		}

		i_stream_skip(input, i);
	}
}

static int verify_header(struct mail_index *index,
			 struct mail_index_record *rec,
			 unsigned int uid, unsigned char current_digest[16])
{
	const void *old_digest;
	size_t size;

	if (uid != 0) {
		/* X-UID header - no need to check more */
		return uid == rec->uid;
	}

	/* check if MD5 sums match */
	if (!mail_cache_lookup_field(index->cache, rec, MAIL_CACHE_MD5,
				     &old_digest, &size))
		return FALSE;

	return memcmp(old_digest, current_digest, 16) == 0;
}

static int mbox_check_uidvalidity(struct mail_index *index,
				  unsigned int uid_validity)
{
	if (uid_validity == index->header->uid_validity)
		return TRUE;

	index->header->flags |= MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES |
		MAIL_INDEX_HDR_FLAG_DIRTY_CUSTOMFLAGS;

	if (uid_validity == 0) {
		/* X-IMAPbase header isn't written yet */
	} else {
		/* UID validity has changed - rebuild whole index */
		index->set_flags |= MAIL_INDEX_HDR_FLAG_REBUILD;
		index->inconsistent = TRUE;
		return FALSE;
	}

	return TRUE;
}

static int match_next_record(struct mail_index *index,
			     struct mail_index_record *rec,
			     unsigned int *seq, struct istream *input,
			     struct mail_index_record **next_rec, int *dirty)
{
	struct mbox_header_context ctx;
	struct mail_index_record *first_rec, *last_rec;
	struct istream *hdr_input;
        enum mail_index_record_flag index_flags;
	uoff_t header_offset, body_offset, offset, body_size, eoh_offset;
	unsigned char current_digest[16];
	unsigned int first_seq, last_seq;
	int ret, hdr_parsed;

	*next_rec = NULL;

	/* skip the From-line */
	skip_line(input);
	header_offset = input->v_offset;

	first_rec = last_rec = NULL;
	first_seq = last_seq = 0;
	ret = 0; body_offset = 0; eoh_offset = (uoff_t)-1; hdr_parsed = FALSE;
	do {
		if (!mbox_mail_get_location(index, rec, &offset, &body_size))
			return -1;

		if (body_size == 0 && eoh_offset == (uoff_t)-1) {
			/* possibly broken message, find the next From-line
			   and make sure header parser won't pass it. */
			i_stream_seek(input, header_offset);
			mbox_skip_header(input);
			eoh_offset = input->v_offset;
			hdr_parsed = FALSE;
		}

		if (!hdr_parsed) {
			/* get the MD5 sum of fixed headers and the current
			   message flags in Status and X-Status fields */
			if (eoh_offset == (uoff_t)-1)
				hdr_input = input;
			else {
				hdr_input = i_stream_create_limit(default_pool,
						input, 0, eoh_offset);
			}
			i_stream_seek(hdr_input, header_offset);

			mbox_header_init_context(&ctx, index, hdr_input);
			message_parse_header(NULL, hdr_input, NULL,
					     mbox_header_cb, &ctx);

			hdr_parsed = TRUE;
			body_offset = hdr_input->v_offset;

			if (eoh_offset != (uoff_t)-1)
				i_stream_unref(hdr_input);
			hdr_input = NULL;
			md5_final(&ctx.md5, current_digest);

			if (*seq == 1) {
				if (!mbox_check_uidvalidity(index,
							    ctx.uid_validity)) {
					/* uidvalidity changed, abort */
					return -1;
				}

				if (ctx.uid_last >= index->header->next_uid) {
					/* last_uid larger than ours */
					index->header->next_uid =
						ctx.uid_last+1;
				}
			}
		}

		if (verify_header(index, rec, ctx.uid, current_digest) &&
		    mbox_verify_end_of_body(input, body_offset + body_size)) {
			/* valid message */

			/* update flags, unless we've changed them */
			index_flags =
				mail_cache_get_index_flags(index->cache, rec);
			if ((index_flags & MAIL_INDEX_FLAG_DIRTY) == 0) {
				if (!index->update_flags(index, rec, *seq,
							 MODIFY_REPLACE,
							 ctx.flags, TRUE))
					return -1;
			} else if (rec->msg_flags == ctx.flags) {
				/* flags are same, it's not dirty anymore */
				index_flags &= ~MAIL_INDEX_FLAG_DIRTY;
				mail_cache_update_index_flags(index->cache,
							      rec, index_flags);
			} else {
				*dirty = TRUE;
			}

			/* update location */
			if (offset != header_offset) {
				if (!mail_cache_update_location_offset(
					index->cache, rec, header_offset))
					return -1;
			}
			ret = 1;
			break;
		}

		/* try next message */
		if (first_rec == NULL) {
			first_rec = rec;
			first_seq = *seq;
		}
		last_rec = rec;
		last_seq = *seq;

		rec = index->next(index, rec); *seq += 1;
	} while (rec != NULL);

	if (first_rec == NULL) {
		*seq += 1;
		*next_rec = rec == NULL ? NULL : index->next(index, rec);
	} else {
		if (!index->expunge(index, first_rec, last_rec,
				    first_seq, last_seq, TRUE))
			return -1;

		*seq = first_seq + 1;
		*next_rec = index->lookup(index, *seq);
	}

	return ret;
}

static int mbox_sync_from_stream(struct mail_index *index,
				 struct istream *input)
{
	struct mail_index_record *rec;
	uoff_t from_offset;
	const unsigned char *data;
	size_t size;
	unsigned int seq;
	int dirty, ret;

	if (mail_cache_lock(index->cache, FALSE) <= 0)
		return -1;
	mail_cache_unlock_later(index->cache);

	mbox_skip_empty_lines(input);

	/* first make sure we start with a "From " line. If file is too
	   small, we'll just treat it as empty mbox file. */
	if (i_stream_read_data(input, &data, &size, 5) > 0 &&
	    memcmp(data, "From ", 5) != 0) {
		index_set_error(index, "File isn't in mbox format: %s",
				index->mailbox_path);
		return -1;
	}

	/* we'll go through the mailbox and index in order matching the
	   messages by their size and Message-ID. old mails aren't remembered,
	   so we handle well only the cases when mail has been deleted. if
	   mails have been reordered (eg. sorted by someone) most of the mails
	   will show up as being new. if we really wanted to support that well,
	   we could save the message-ids into hash but I don't know if it's
	   worth the trouble. */

	seq = 1;
	rec = index->lookup(index, 1);

	dirty = FALSE;
	while (rec != NULL) {
		from_offset = input->v_offset;
		if (input->v_offset != 0) {
			/* we're at the [\r]\n before the From-line,
			   skip it */
			if (!mbox_skip_crlf(input)) {
				/* they just went and broke it, even while
				   we had it locked. */
				index_set_error(index,
						"Error syncing mbox file %s: "
						"LF not found where expected",
						index->mailbox_path);
				return -1;
			}
		}

		ret = match_next_record(index, rec, &seq, input, &rec, &dirty);
		if (ret < 0)
			return -1;

		if (ret == 0) {
			/* Get back to line before From */
			i_stream_seek(input, from_offset);
		}
	}

	/* delete the rest of the records */
	if (rec != NULL) {
		if (!index->expunge(index, rec, INDEX_END_RECORD(index)-1,
				    seq, index->header->messages_count, TRUE))
			return -1;
	}

	if (!dirty &&
	    (index->header->flags & MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES)) {
		/* no flags are dirty anymore, no need to rewrite */
		index->header->flags &= ~MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
	}

	if ((index->set_flags & MAIL_INDEX_HDR_FLAG_REBUILD))
		return 1;
	else
		return mbox_index_append_stream(index, input);
}

int mbox_sync_full(struct mail_index *index)
{
	struct istream *input;
	struct stat orig_st, st;
	uoff_t continue_offset;
	int ret, failed;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	input = mbox_get_stream(index, MAIL_LOCK_SHARED);
	if (input == NULL)
		return FALSE;

	if (fstat(index->mbox_fd, &orig_st) < 0) {
		mbox_set_syscall_error(index, "fstat()");
		continue_offset = (uoff_t)-1;
		failed = TRUE;
	} else {
		ret = mbox_sync_from_stream(index, input);
		failed = ret < 0;
		continue_offset = ret != 0 ||
			(index->set_flags & MAIL_INDEX_HDR_FLAG_REBUILD) ?
			(uoff_t)-1 : input->v_offset;
		i_stream_unref(input);
	}

	if (continue_offset != (uoff_t)-1) {
		/* mbox_index_append() stopped, which means that it wants
		   write access to mbox. if mbox hasn't changed after
		   unlock+lock, we should be able to safely continue where we
		   were left off last time. otherwise do full resync. */
		if (!mbox_unlock(index))
			return FALSE;

		input = mbox_get_stream(index, MAIL_LOCK_EXCLUSIVE);
		if (input == NULL)
			return FALSE;

		if (fstat(index->mbox_fd, &st) < 0) {
			mbox_set_syscall_error(index, "fstat()");
			failed = TRUE;
		} else if (st.st_mtime == orig_st.st_mtime &&
			   st.st_size == orig_st.st_size) {
			i_stream_seek(input, continue_offset);
			failed = mbox_index_append_stream(index, input) <= 0;
		} else {
			failed = mbox_sync_from_stream(index, input) <= 0;
		}

		if (index->mbox_rewritten) {
			/* rewritten, sync again */
                        index->mbox_rewritten = FALSE;
			i_stream_seek(input, 0);
			failed = mbox_sync_from_stream(index, input) <= 0;
		}

		i_stream_unref(input);
	}

	return !failed;
}
