/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "index-storage.h"
#include "index-messageset.h"

#include <unistd.h>

typedef struct {
	Mailbox *dest;
	const char **custom_flags;
} CopyData;

static int copy_func(MailIndex *index, MailIndexRecord *rec,
		     unsigned int seq __attr_unused__, void *context)
{
	CopyData *cd = context;
	IOBuffer *inbuf;
	int failed;

	inbuf = index->open_mail(index, rec);
	if (inbuf == NULL)
		return FALSE;

	/* save it in destination mailbox */
	failed = !cd->dest->save(cd->dest, rec->msg_flags,
				 cd->custom_flags, rec->internal_date,
				 inbuf, inbuf->size);
	(void)close(inbuf->fd);
	io_buffer_destroy(inbuf);
	return !failed;
}

int index_storage_copy(Mailbox *box, Mailbox *destbox,
		       const char *messageset, int uidset)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
        CopyData cd;
	int failed;

	if (destbox->readonly) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return FALSE;
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	cd.custom_flags = flags_file_list_get(ibox->flagsfile);
	cd.dest = destbox;

	failed = index_messageset_foreach(ibox, messageset, uidset,
					  copy_func, &cd) <= 0;

	flags_file_list_unref(ibox->flagsfile);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return !failed;
}
