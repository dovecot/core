/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-messageset.h"
#include "maildir-index.h"
#include "maildir-storage.h"
#include "mail-custom-flags.h"

#include <stdlib.h>
#include <unistd.h>

typedef struct {
	MailStorage *storage;
	IndexMailbox *dest;
	int error;
	const char **custom_flags;
} CopyHardContext;

static int copy_hard_func(MailIndex *index, MailIndexRecord *rec,
			  unsigned int client_seq __attr_unused__,
			  unsigned int idx_seq __attr_unused__, void *context)
{
	CopyHardContext *ctx = context;
	MailFlags flags;
	const char *fname;
	char src[1024], dest[1024];

	flags = rec->msg_flags;
	if (!index_mailbox_fix_custom_flags(ctx->dest, &flags,
					    ctx->custom_flags))
		return FALSE;

	/* link the file */
	fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	i_snprintf(src, sizeof(src), "%s/cur/%s", index->dir, fname);

	fname = maildir_filename_set_flags(fname, flags);
	i_snprintf(dest, sizeof(dest), "%s/new/%s",
		   ctx->dest->index->dir, fname);

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

	if (!src->index->sync(src->index))
		return mail_storage_set_index_error(src);

	if (!src->index->set_lock(src->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(src);
	if (!dest->index->set_lock(dest->index, MAIL_LOCK_EXCLUSIVE)) {
		(void)src->index->set_lock(src->index, MAIL_LOCK_UNLOCK);
		return mail_storage_set_index_error(dest);
	}

	ctx.storage = src->box.storage;
	ctx.dest = dest;
	ctx.error = FALSE;
	ctx.custom_flags = mail_custom_flags_list_get(src->index->custom_flags);

	ret = index_messageset_foreach(src, messageset, uidset,
				       copy_hard_func, &ctx);

	if (!dest->index->set_lock(dest->index, MAIL_LOCK_UNLOCK))
		mail_storage_set_index_error(dest);

	if (!src->index->set_lock(src->index, MAIL_LOCK_UNLOCK))
		mail_storage_set_index_error(src);

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

	if (getenv("MAILDIR_COPY_WITH_HARDLINKS") != NULL &&
	    destbox->storage == box->storage) {
		/* both source and destination mailbox are in maildirs and
		   copy_with_hardlinks option is on, do it */
		switch (maildir_copy_with_hardlinks(ibox,
			(IndexMailbox *) destbox, messageset, uidset)) {
		case 1:
			return TRUE;
		case 0:
			/* non-fatal hardlinking failure, try the slow way */
			break;
		default:
			return FALSE;
		}
	}

	return index_storage_copy(box, destbox, messageset, uidset);
}
