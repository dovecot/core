/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-messageset.h"
#include "maildir-storage.h"

#include <stdlib.h>
#include <unistd.h>

typedef struct {
	MailStorage *storage;
	const char *dest_maildir;
	int error;
} CopyHardData;

static int copy_hard_func(MailIndex *index, MailIndexRecord *rec,
			  unsigned int seq __attr_unused__, void *user_data)
{
	CopyHardData *data = user_data;
	const char *fname;
	char src[1024], dest[1024];

	/* link the file */
	fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	i_snprintf(src, sizeof(src), "%s/cur/%s", index->dir, fname);
	i_snprintf(dest, sizeof(dest), "%s/new/%s", data->dest_maildir, fname);

	if (link(src, dest) == 0)
		return TRUE;
	else {
		if (errno != EXDEV) {
			mail_storage_set_critical(data->storage, "link(%s, %s) "
						  "failed: %m", src, dest);
			data->error = TRUE;
		}
		return FALSE;
	}
}

static int maildir_copy_with_hardlinks(IndexMailbox *src,
				       IndexMailbox *dest,
				       const char *messageset, int uidset)
{
        CopyHardData data;
	int ret;

	if (!src->index->set_lock(src->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(src);
	if (!dest->index->set_lock(dest->index, MAIL_LOCK_EXCLUSIVE)) {
		(void)src->index->set_lock(src->index, MAIL_LOCK_UNLOCK);
		return mail_storage_set_index_error(dest);
	}

	data.storage = src->box.storage;
	data.dest_maildir = dest->index->dir;
	data.error = FALSE;

	if (uidset) {
		ret = mail_index_uidset_foreach(src->index, messageset,
						src->synced_messages_count,
						copy_hard_func, &data);
	} else {
		ret = mail_index_messageset_foreach(src->index, messageset,
						    src->synced_messages_count,
						    copy_hard_func, &data);
	}

	if (ret == -1)
		mail_storage_set_index_error(src);

	if (!dest->index->set_lock(dest->index, MAIL_LOCK_UNLOCK)) {
		mail_storage_set_index_error(dest);
		ret = -1;
	}

	if (!src->index->set_lock(src->index, MAIL_LOCK_SHARED)) {
		mail_storage_set_index_error(src);
		ret = -1;
	}

	return data.error ? -1 : ret;
}

int maildir_storage_copy(Mailbox *box, Mailbox *destbox,
			 const char *messageset, int uidset)
{
	IndexMailbox *ibox = (IndexMailbox *) box;

	if (destbox->readonly) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return FALSE;
	}

	if (getenv("COPY_WITH_HARDLINKS") != NULL &&
	    destbox->storage == box->storage) {
		/* both source and destination mailbox are in maildirs and
		   copy_with_hardlinks option is on, do it */
		switch (maildir_copy_with_hardlinks(ibox,
			(IndexMailbox *) destbox, messageset, uidset)) {
		case -1:
			return FALSE;
		case 1:
			return TRUE;
		}

		/* non-fatal hardlinking failure, try the slow way */
	}

	return index_storage_copy(box, destbox, messageset, uidset);
}
