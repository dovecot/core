/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "maildir-storage.h"
#include "mail-custom-flags.h"
#include "mail-index-util.h"
#include "index-messageset.h"

#include <stdlib.h>
#include <unistd.h>

static int hardlink_messageset(struct messageset_context *ctx,
			       struct index_mailbox *src,
			       struct index_mailbox *dest)
{
        struct mail_index *index = src->index;
        const struct messageset_mail *mail;
	enum mail_flags flags;
	const char **custom_flags;
	const char *fname, *src_fname, *dest_fname;

	custom_flags = mail_custom_flags_list_get(index->custom_flags);

	while ((mail = index_messageset_next(ctx)) != NULL) {
		flags = mail->rec->msg_flags;
		if (!index_mailbox_fix_custom_flags(dest, &flags,
						    custom_flags,
						    MAIL_CUSTOM_FLAGS_COUNT))
			return -1;

		/* link the file */
		fname = index->lookup_field(index, mail->rec,
					    DATA_FIELD_LOCATION);
		if (fname == NULL) {
			index_set_corrupted(index,
				"Missing location field for record %u",
				mail->rec->uid);
			return -1;
		}

		t_push();
		src_fname = t_strconcat(index->mailbox_path, "cur/",
					fname, NULL);
		dest_fname = t_strconcat(dest->index->mailbox_path, "new/",
                	maildir_filename_set_flags(
				maildir_generate_tmp_filename(), flags), NULL);

		if (link(src_fname, dest_fname) < 0) {
			if (errno != EXDEV) {
				mail_storage_set_critical(src->box.storage,
					"link(%s, %s) failed: %m",
					src_fname, dest_fname);
				t_pop();
				return -1;
			}
			t_pop();
			return 0;
		}
		t_pop();
	}

	return 1;
}

static int copy_with_hardlinks(struct index_mailbox *src,
			       struct index_mailbox *dest,
			       const char *messageset, int uidset)
{
        struct messageset_context *ctx;
	int ret;

	if (!index_storage_sync_and_lock(src, TRUE, MAIL_LOCK_SHARED))
		return -1;

	ctx = index_messageset_init(src, messageset, uidset);
	ret = hardlink_messageset(ctx, src, dest);
	if (index_messageset_deinit(ctx) < 0)
		ret = -1;

	(void)index_storage_lock(src, MAIL_LOCK_UNLOCK);

	return ret;
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
		switch (copy_with_hardlinks(ibox,
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
