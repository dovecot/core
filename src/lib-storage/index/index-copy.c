/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "index-storage.h"
#include "mail-messageset.h"

#include <unistd.h>

typedef struct {
	Mailbox *dest;
	const char **custom_flags;
} CopyData;

static int copy_func(MailIndex *index, MailIndexRecord *rec,
		     unsigned int seq __attr_unused__, void *user_data)
{
	CopyData *cd = user_data;
	IOBuffer *buf;
	off_t offset;
	size_t size;
	int fd, failed;

	fd = index->open_mail(index, rec, &offset, &size);
	if (fd == -1)
		return FALSE;

	/* save it in destination mailbox */
	buf = io_buffer_create_file(fd, default_pool, 4096);
	failed = !cd->dest->save(cd->dest, rec->msg_flags,
				 cd->custom_flags, rec->internal_date,
				 buf, size);

	(void)close(fd);
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

	if (uidset) {
		failed = mail_index_uidset_foreach(ibox->index, messageset,
						   ibox->synced_messages_count,
						   copy_func, destbox) <= 0;
	} else {
		failed = mail_index_messageset_foreach(ibox->index, messageset,
			ibox->synced_messages_count, copy_func, destbox) <= 0;
	}

	flags_file_list_unref(ibox->flagsfile);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || failed)
		return mail_storage_set_index_error(ibox);

	return TRUE;
}

