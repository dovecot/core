/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec, int *deleted)
{
	IBuffer *inbuf;
	uoff_t offset;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	if (!mbox_mail_get_start_offset(index, rec, &offset))
		return NULL;

	inbuf = mbox_get_inbuf(index, offset, MAIL_LOCK_SHARED);
	if (inbuf == NULL)
		return NULL;

	i_assert(index->mbox_sync_counter == index->mbox_lock_counter);

	i_buffer_set_read_limit(inbuf, rec->header_size + rec->body_size);
	return inbuf;
}
