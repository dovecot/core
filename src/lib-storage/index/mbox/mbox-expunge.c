/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "mbox-index.h"
#include "mbox-storage.h"
#include "mbox-lock.h"

#include <fcntl.h>
#include <unistd.h>

static int expunge_real(struct index_mailbox *ibox,
			struct mail_index_record *rec, unsigned int seq,
			struct istream *input, struct ostream *output,
			int notify)
{
	uoff_t offset, hdr_size, body_size;
	uoff_t end_offset, from_offset, copy_size, old_limit;
	const unsigned char *data;
	size_t size;
	int expunges, failed;

	if (seq == 1)
		end_offset = 0;
	else {
		/* we need to find offset to beginning of From-line.
		   not the fastest way maybe, but easiest.. */
		rec = ibox->index->lookup(ibox->index, seq-1);
		
		if (!mbox_mail_get_location(ibox->index, rec, &offset,
					    &hdr_size, &body_size))
			return FALSE;
		end_offset = offset + hdr_size + body_size;

		/* get back to the deleted record */
		rec = ibox->index->next(ibox->index, rec);
	}

	old_limit = input->v_limit;

	expunges = FALSE;
	while (rec != NULL) {
		if (!mbox_mail_get_location(ibox->index, rec, &offset,
					    &hdr_size, &body_size))
			return FALSE;

		from_offset = end_offset;
		end_offset = offset + hdr_size + body_size;

		if (rec->msg_flags & MAIL_DELETED) {
			if (!index_expunge_mail(ibox, rec, seq, notify))
				return FALSE;
			seq--;

			if (!expunges) {
				/* first expunged record, seek to position
				   where we want to begin writing */
				if (o_stream_seek(output, from_offset) < 0)
					return FALSE;
				expunges = TRUE;
			}
		} else if (expunges) {
			/* seek to wanted input position, and copy
			   this messages */
			i_assert(input->v_offset <= from_offset);
			i_stream_skip(input, from_offset - input->v_offset);

			if (output->offset == 0) {
				/* we're writing to beginning of mbox, so we
				   don't want the [\r]\n there */
				(void)i_stream_read_data(input, &data,
							 &size, 1);
				if (size > 0 && data[0] == '\n')
					i_stream_skip(input, 1);
				else if (size > 1 && data[0] == '\r' &&
					 data[1] == '\n')
					i_stream_skip(input, 2);
			}

			i_stream_set_read_limit(input, end_offset);
			failed = o_stream_send_istream(output, input) < 0;
			i_stream_set_read_limit(input, old_limit);

			if (failed || input->v_offset != end_offset)
				return FALSE;
		}

		rec = ibox->index->next(ibox->index, rec);
		seq++;
	}

	i_stream_skip(input, end_offset - input->v_offset);

	/* copy the rest as well, should be only \n but someone might
	   as well just appended more data.. but if we've deleted all mail,
	   don't write the only \n there. */
	copy_size = input->v_size - input->v_offset;
	if (output->offset == 0 && copy_size == 1)
		return TRUE;

	return o_stream_send_istream(output, input) >= 0;
}

int mbox_expunge_locked(struct index_mailbox *ibox, int notify)
{
	struct mail_index_record *rec;
	struct istream *input;
	struct ostream *output;
	unsigned int seq;
	int failed;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	if (rec == NULL) {
		/* no deleted messages */
		return TRUE;
	}

	/* mbox must be already opened, synced and locked at this point.
	   we just want the istream. */
	input = mbox_get_stream(ibox->index, 0, MAIL_LOCK_EXCLUSIVE);
	if (input == NULL)
		return FALSE;

	i_assert(ibox->index->mbox_sync_counter ==
		 ibox->index->mbox_lock_counter);

	t_push();
	output = o_stream_create_file(ibox->index->mbox_fd, data_stack_pool,
				      4096, 0, FALSE);
	o_stream_set_blocking(output, 60000, NULL, NULL);

	failed = !expunge_real(ibox, rec, seq, input, output, notify);

	if (failed && output->offset > 0) {
		/* we moved some of the data. move the rest as well so there
		   won't be invalid holes in mbox file */
		(void)o_stream_send_istream(output, input);
	}

	if (ftruncate(ibox->index->mbox_fd, (off_t)output->offset) < 0) {
		mail_storage_set_error(ibox->box.storage, "ftruncate() failed "
				       "for mbox file %s: %m",
				       ibox->index->mailbox_path);
		failed = TRUE;
	}

	o_stream_unref(output);
	t_pop();

	return !failed;
}
