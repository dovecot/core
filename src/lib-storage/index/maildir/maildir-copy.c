/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-messageset.h"
#include "maildir-storage.h"

#include <stdlib.h>
#include <unistd.h>

typedef struct {
	MailStorage *storage;
	const char *dest_maildir;
	int error;
} CopyHardContext;

static int copy_hard_func(MailIndex *index, MailIndexRecord *rec,
			  unsigned int seq __attr_unused__, void *context)
{
	CopyHardContext *ctx = context;
	const char *fname;
	char src[1024], dest[1024];

	/* link the file */
	fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	i_snprintf(src, sizeof(src), "%s/cur/%s", index->dir, fname);
	i_snprintf(dest, sizeof(dest), "%s/new/%s", ctx->dest_maildir, fname);

	if (link(src, dest) == 0)
		return TRUE;
	else {
		if (errno != EXDEV) {
			mail_storage_set_critical(ctx->storage, "link(%s, %s) "
						  "failed: %m", src, dest);
			ctx->error = TRUE;
		}
		return FALSE;
	}
}

static int maildir_copy_with_hardlinks(IndexMailbox *src,
				       IndexMailbox *dest,
				       const char *messageset, int uidset)
{
	CopyHardContext ctx;
	int ret;

	if (!src->index->set_lock(src->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(src);
	if (!dest->index->set_lock(dest->index, MAIL_LOCK_EXCLUSIVE)) {
		(void)src->index->set_lock(src->index, MAIL_LOCK_UNLOCK);
		return mail_storage_set_index_error(dest);
	}

	ctx.storage = src->box.storage;
	ctx.dest_maildir = dest->index->dir;
	ctx.error = FALSE;

	ret = index_messageset_foreach(src, messageset, uidset,
				       copy_hard_func, &ctx) <= 0;

	if (!dest->index->set_lock(dest->index, MAIL_LOCK_UNLOCK)) {
		mail_storage_set_index_error(dest);
		ret = -1;
	}

	if (!src->index->set_lock(src->index, MAIL_LOCK_SHARED)) {
		mail_storage_set_index_error(src);
		ret = -1;
	}

	return ctx.error ? -1 : ret;
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
		case -2:
			return FALSE;
		case 1:
			return TRUE;
		}

		/* non-fatal hardlinking failure, try the slow way */
	}

	return index_storage_copy(box, destbox, messageset, uidset);
}
