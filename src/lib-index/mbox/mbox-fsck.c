/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "message-parser.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <fcntl.h>

typedef struct {
	const char *msgid;
	MailFlags flags;
} HeaderContext;

static void header_func(MessagePart *part __attr_unused__,
			const char *name, unsigned int name_len,
			const char *value, unsigned int value_len,
			void *context)
{
	HeaderContext *ctx = context;

	if (name_len != 10 || strncasecmp(name, "Message-ID", 10) != 0)
		return;

	ctx->msgid = t_strndup(value, value_len);
	ctx->flags |= mbox_header_get_flags(name, name_len, value, value_len);
}

static MailIndexRecord *
match_next_record(MailIndex *index, MailIndexRecord *rec, unsigned int *seq,
		  const char **data, const char *data_end)
{
#if 0 // FIXME
	MessageSize hdr_size;
        HeaderData hdr_data;
	const char *rec_msgid, *data_next;

	/* skip the From-line */
	while (*data != data_end && **data != '\n')
		(*data)++;
	(*data)++;

	if (*data >= data_end) {
		/* end of data */
		(void)index->expunge(index, rec, *seq, TRUE);
		return rec;
	}

	/* find the Message-ID from the header */
	memset(&hdr_data, 0, sizeof(hdr_data));
	message_parse_header(NULL, *data, (size_t) (data_end-*data), &hdr_size,
			     header_func, &hdr_data);

	do {
		do {
			/* message-id must match (or be non-existant) */
			rec_msgid = index->lookup_field(index, rec,
							FIELD_TYPE_MESSAGEID);
			if (hdr_data.msgid == NULL && rec_msgid != NULL)
				break;
			if (hdr_data.msgid != NULL &&
			    (rec_msgid == NULL ||
			     strcmp(hdr_data.msgid, rec_msgid) != 0))
				break;

			/* don't bother parsing the whole body, just make
			   sure it ends properly */
			data_next = *data + rec->header_size + rec->body_size;
			if (data_next == data_end) {
				/* last message */
			} else if (data_next+5 >= data_end ||
				   strncmp(data_next-1, "\nFrom ", 6) != 0)
				break;

			/* valid message, update flags */
			if ((rec->msg_flags & hdr_data.flags) != hdr_data.flags)
				rec->msg_flags |= hdr_data.flags;

			*data = data_next;
			return rec;
		} while (0);

		/* try next message */
		(*seq)++;
		(void)index->expunge(index, rec, *seq, TRUE);
		rec = index->next(index, rec);
	} while (rec != NULL);
#endif
	return NULL;
}

static int mbox_index_fsck_mmap(MailIndex *index, const char *data, size_t size)
{
	MailIndexRecord *rec;
	const char *data_end;
	unsigned int seq;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* first make sure we start with a "From " line. */
	if (size <= 5 || strncmp(data, "From ", 5) != 0) {
		index_set_error(index, "File isn't in mbox format: %s",
				index->mbox_path);
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

	data_end = data + size;
	while (rec != NULL) {
		rec = match_next_record(index, rec, &seq, &data, data_end);
		if (rec == NULL)
			break;

		seq++;
		rec = index->next(index, rec);
	}

	if (data == data_end)
		return TRUE;
	else {
		return mbox_index_append_mmaped(index, data,
						(size_t) (data_end-data), 0);
	}
}

int mbox_index_fsck(MailIndex *index)
{
	void *mmap_base;
	size_t mmap_length;
	int fd, failed;

	/* open the mbox file. we don't really need to open it read-write,
	   but fcntl() locking requires it. */
	fd = open(index->mbox_path, O_RDWR);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	mmap_base = mmap_ro_file(fd, &mmap_length);
	if (mmap_base == MAP_FAILED) {
		index_set_error(index, "mmap() failed with mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}
	(void)madvise(mmap_base, mmap_length, MADV_SEQUENTIAL);

	if (mmap_base == NULL) {
		/* file is empty */
		(void)close(fd);
		return TRUE;
	}

	/* lock the mailbox so we can be sure no-one interrupts us.
	   we are trying to repair our index after all. */
	if (!mbox_lock(index, index->mbox_path, fd))
		failed = TRUE;
	else {
		failed = !mbox_index_fsck_mmap(index, mmap_base, mmap_length);
		(void)mbox_unlock(index, index->mbox_path, fd);
	}

	(void)munmap(mmap_base, mmap_length);
	(void)close(fd);

	if (failed)
		return FALSE;

	/* check the header */
	return mail_index_fsck(index);
}
