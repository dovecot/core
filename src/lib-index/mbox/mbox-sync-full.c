/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "hex-binary.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void skip_line(struct istream *input)
{
	const unsigned char *msg;
	size_t i, size;

	while (i_stream_read_data(input, &msg, &size, 0) > 0) {
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
	const unsigned char *old_digest;
	size_t size;

	/* MD5 sums must match */
	old_digest = index->lookup_field_raw(index, rec, DATA_FIELD_MD5, &size);
	if (old_digest == NULL)
		return uid == rec->uid;

	return size >= 16 && memcmp(old_digest, current_digest, 16) == 0 &&
		(uid == 0 || uid == rec->uid);
}

static int mail_update_header_size(struct mail_index *index,
				   struct mail_index_record *rec,
				   struct mail_index_update *update,
				   struct message_size *hdr_size)
{
	const void *part_data;
	const char *error;
	void *part_data_copy;
	uoff_t virtual_size;
	size_t size;

	/* update FIELD_HDR_HEADER_SIZE */
	index->update_field_raw(update, DATA_HDR_HEADER_SIZE,
				&hdr_size->physical_size,
				sizeof(hdr_size->physical_size));

	/* reset FIELD_HDR_VIRTUAL_SIZE - we don't know it anymore */
        virtual_size = (uoff_t)-1;
	index->update_field_raw(update, DATA_HDR_VIRTUAL_SIZE,
				&virtual_size, sizeof(virtual_size));

	/* update DATA_FIELD_MESSAGEPART */
	if ((rec->data_fields & DATA_FIELD_MESSAGEPART) == 0)
		return TRUE;

	part_data = index->lookup_field_raw(index, rec, DATA_FIELD_MESSAGEPART,
					    &size);
	if (part_data == NULL) {
		/* well, this wasn't expected but don't bother failing */
		return TRUE;
	}

	t_push();

	/* copy & update the part data */
	part_data_copy = t_malloc(size);
	memcpy(part_data_copy, part_data, size);

	if (!message_part_serialize_update_header(part_data_copy, size,
						  hdr_size, &error)) {
		index_set_corrupted(index,
				    "Corrupted cached message_part data (%s)",
				    error);
		t_pop();
		return FALSE;
	}

	index->update_field_raw(update, DATA_FIELD_MESSAGEPART,
				part_data_copy, size);
	t_pop();
	return TRUE;
}

static int mbox_check_uidvalidity(struct mail_index *index,
				  unsigned int uid_validity)
{
	if (uid_validity == index->header->uid_validity)
		return TRUE;

	index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES |
		MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS;

	if (uid_validity == 0) {
		/* X-IMAPbase header isn't written yet */
	} else {
		/* UID validity has changed - rebuild whole index */
		index->set_flags |= MAIL_INDEX_FLAG_REBUILD;
		return FALSE;
	}

	return TRUE;
}

static int match_next_record(struct mail_index *index,
			     struct mail_index_record *rec,
			     unsigned int seq, struct istream *input,
			     struct mail_index_record **next_rec, int *dirty)
{
        struct mail_index_update *update;
	struct message_size hdr_parsed_size;
	struct mbox_header_context ctx;
	uoff_t header_offset, body_offset, offset;
	uoff_t hdr_size, body_size;
	unsigned char current_digest[16];
	int hdr_size_fixed;

	*next_rec = NULL;

	/* skip the From-line */
	skip_line(input);
	header_offset = input->v_offset;

	hdr_size = 0; body_offset = 0; hdr_size_fixed = FALSE;
	do {
		if (!mbox_mail_get_location(index, rec, NULL, NULL, &body_size))
			return FALSE;

		i_stream_seek(input, header_offset);

		if (body_size == 0 && !hdr_size_fixed) {
			/* possibly broken message, find the next From-line
			   and make sure header parser won't pass it. */
			mbox_skip_header(input);
			i_stream_set_read_limit(input, input->v_offset);
			i_stream_seek(input, header_offset);
			hdr_size_fixed = TRUE;
			hdr_size = 0;
		}

		if (hdr_size == 0) {
			/* get the MD5 sum of fixed headers and the current
			   message flags in Status and X-Status fields */
			mbox_header_init_context(&ctx, index, input);
			message_parse_header(NULL, input, &hdr_parsed_size,
					     mbox_header_cb, &ctx);
			md5_final(&ctx.md5, current_digest);

			if (seq == 1) {
				if (!mbox_check_uidvalidity(index,
							    ctx.uid_validity)) {
					/* uidvalidity changed, abort */
					break;
				}

				if (ctx.uid_last >= index->header->next_uid) {
					/* last_uid larger than ours */
					index->header->next_uid =
						ctx.uid_last+1;
				}
			}

			mbox_header_free_context(&ctx);
			i_stream_set_read_limit(input, 0);

			body_offset = input->v_offset;
		}

		if (verify_header(index, rec, ctx.uid, current_digest) &&
		    mbox_verify_end_of_body(input, body_offset + body_size)) {
			/* valid message */
			update = index->update_begin(index, rec);

			/* update flags, unless we've changed them */
			if ((rec->index_flags & INDEX_MAIL_FLAG_DIRTY) == 0) {
				if (!index->update_flags(index, rec, seq,
							 ctx.flags, TRUE))
					return FALSE;

				/* update_flags() sets dirty flag, remove it */
				rec->index_flags &= ~INDEX_MAIL_FLAG_DIRTY;
			} else {
				if (rec->msg_flags != ctx.flags)
					*dirty = TRUE;
			}

			/* update location */
			if (!mbox_mail_get_location(index, rec, &offset,
						    NULL, NULL))
				return FALSE;
			if (offset != header_offset) {
				index->update_field_raw(update,
							DATA_FIELD_LOCATION,
							&header_offset,
							sizeof(uoff_t));
			}

			/* update size */
			if (hdr_size != hdr_parsed_size.physical_size ) {
				if (!mail_update_header_size(index, rec, update,
							     &hdr_parsed_size))
					return FALSE;
			}

			if (!index->update_end(update))
				return FALSE;

			*next_rec = rec;
			break;
		}

		/* try next message */
		(void)index->expunge(index, rec, seq, TRUE);
		rec = index->next(index, rec);
	} while (rec != NULL);

	return TRUE;
}

static int mbox_sync_from_stream(struct mail_index *index,
				 struct istream *input)
{
	struct mail_index_record *rec;
	uoff_t from_offset;
	const unsigned char *data;
	size_t size;
	unsigned int seq;
	int dirty;

	mbox_skip_empty_lines(input);

	/* first make sure we start with a "From " line. If file is too
	   small, we'll just treat it as empty mbox file. */
	if (i_stream_read_data(input, &data, &size, 5) > 0 &&
	    memcmp(data, "From ", 5) != 0) {
		index_set_error(index, "File isn't in mbox format: %s",
				index->mailbox_path);
		return FALSE;
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
				return FALSE;
			}
		}

		if (input->v_offset == input->v_size)
			break;

		if (!match_next_record(index, rec, seq, input, &rec, &dirty))
			return FALSE;

		if (rec == NULL) {
			/* Get back to line before From */
			i_stream_seek(input, from_offset);
			break;
		}

		seq++;
		rec = index->next(index, rec);
	}

	/* delete the rest of the records */
	while (rec != NULL) {
		(void)index->expunge(index, rec, seq, TRUE);

		rec = index->next(index, rec);
	}

	if (!dirty && (index->header->flags & MAIL_INDEX_FLAG_DIRTY_MESSAGES)) {
		/* no flags are dirty anymore, no need to rewrite */
		index->header->flags &= ~MAIL_INDEX_FLAG_DIRTY_MESSAGES;
	}

	if (input->v_offset == input->v_size ||
	    (index->set_flags & MAIL_INDEX_FLAG_REBUILD))
		return TRUE;
	else
		return mbox_index_append(index, input);
}

int mbox_sync_full(struct mail_index *index)
{
	struct istream *input;
	struct stat orig_st, st;
	uoff_t continue_offset;
	int failed;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	input = mbox_get_stream(index, 0, MAIL_LOCK_SHARED);
	if (input == NULL)
		return FALSE;

	if (fstat(index->mbox_fd, &orig_st) < 0) {
		mbox_set_syscall_error(index, "fstat()");
		continue_offset = (uoff_t)-1;
		failed = TRUE;
	} else {
		failed = !mbox_sync_from_stream(index, input);
		continue_offset = failed || input->v_offset == input->v_size ||
			(index->set_flags & MAIL_INDEX_FLAG_REBUILD) ?
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

		input = mbox_get_stream(index, 0, MAIL_LOCK_EXCLUSIVE);
		if (input == NULL)
			return FALSE;

		if (fstat(index->mbox_fd, &st) < 0) {
			mbox_set_syscall_error(index, "fstat()");
			failed = TRUE;
		} else if (st.st_mtime == orig_st.st_mtime &&
			   st.st_size == orig_st.st_size) {
			i_stream_seek(input, continue_offset);
			failed = !mbox_index_append(index, input);
		} else {
			failed = !mbox_sync_from_stream(index, input);
		}

		i_stream_unref(input);
	}

	return !failed;
}
