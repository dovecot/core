/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mbox-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IStream *mbox_open_mail(MailIndex *index, MailIndexRecord *rec,
			time_t *internal_date, int *deleted)
{
	IStream *input;
	uoff_t offset, hdr_size, body_size;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	if (!mbox_mail_get_location(index, rec, &offset, &hdr_size, &body_size))
		return NULL;

	input = mbox_get_stream(index, offset, MAIL_LOCK_SHARED);
	if (input == NULL)
		return NULL;

	if (internal_date != NULL)
		*internal_date = mail_get_internal_date(index, rec);

	i_assert(index->mbox_sync_counter == index->mbox_lock_counter);

	i_stream_set_read_limit(input, hdr_size + body_size);
	return input;
}
