/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-messageset.h"
#include "maildir-index.h"
#include "maildir-storage.h"
#include "mail-custom-flags.h"

#include <stdlib.h>
#include <unistd.h>

struct copy_hard_context {
	struct mail_storage *storage;
	struct index_mailbox *dest;
	int error;
	const char **custom_flags;
};

static int copy_hard_func(struct mail_index *index,
			  struct mail_index_record *rec,
			  unsigned int client_seq __attr_unused__,
			  unsigned int idx_seq __attr_unused__, void *context)
{
	struct copy_hard_context *ctx = context;
	enum mail_flags flags;
	const char *fname;
	char src[PATH_MAX], dest[PATH_MAX];

	flags = rec->msg_flags;
	if (!index_mailbox_fix_custom_flags(ctx->dest, &flags,
					    ctx->custom_flags))
		return FALSE;

	/* link the file */
	fname = index->lookup_field(index, rec, DATA_FIELD_LOCATION);
	if (str_ppath(src, sizeof(src),
		      index->mailbox_path, "cur/", fname) < 0) {
		mail_storage_set_critical(ctx->storage, "Filename too long: %s",
					  fname);
		return FALSE;
	}

	fname = maildir_filename_set_flags(maildir_generate_tmp_filename(),
					   flags);
	if (str_ppath(dest, sizeof(dest),
		      ctx->dest->index->mailbox_path, "new/", fname) < 0) {
		mail_storage_set_critical(ctx->storage, "Filename too long: %s",
					  fname);
		return FALSE;
	}

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

static int maildir_copy_with_hardlinks(struct index_mailbox *src,
				       struct index_mailbox *dest,
				       const char *messageset, int uidset)
{
	struct copy_hard_context ctx;
	int ret;

	if (!index_storage_sync_and_lock(src, TRUE, MAIL_LOCK_SHARED))
		return -1;

	ctx.storage = src->box.storage;
	ctx.dest = dest;
	ctx.error = FALSE;
	ctx.custom_flags = mail_custom_flags_list_get(src->index->custom_flags);

	ret = index_messageset_foreach(src, messageset, uidset,
				       copy_hard_func, &ctx);

	(void)index_storage_lock(src, MAIL_LOCK_UNLOCK);

	return ctx.error ? -1 : ret;
}

int maildir_storage_copy(struct mailbox *box, struct mailbox *destbox,
			 const char *messageset, int uidset)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

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
			(struct index_mailbox *) destbox, messageset, uidset)) {
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
