/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

struct istream *mbox_open_mail(struct mail_index *index,
			       struct mail_index_record *rec,
			       time_t *received_date, int *deleted)
{
	struct istream *input;
	uoff_t offset, body_size;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	if (!mbox_mail_get_location(index, rec, &offset, &body_size))
		return NULL;

	input = mbox_get_stream(index, offset, MAIL_LOCK_SHARED);
	if (input == NULL)
		return NULL;

	if (received_date != NULL)
		*received_date = index->get_received_date(index, rec);

	i_assert(index->mbox_sync_counter == index->mbox_lock_counter);

	return i_stream_create_mbox(default_pool, input, body_size);
}
