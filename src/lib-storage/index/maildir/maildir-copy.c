/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"
#include "maildir-storage.h"
#include "mail-custom-flags.h"
#include "mail-index-util.h"
#include "index-messageset.h"

#include <stdlib.h>
#include <unistd.h>

struct rollback {
	struct rollback *next;
	const char *fname;
};

static int hardlink_messageset(struct messageset_context *ctx,
			       struct index_mailbox *src,
			       struct index_mailbox *dest)
{
	struct mail_index *index = src->index;
	pool_t pool;
        struct rollback *rollbacks, *rb;
        const struct messageset_mail *mail;
	enum mail_flags flags;
	const char **custom_flags;
	const char *fname, *src_path, *dest_fname, *dest_path;
	int ret;

	pool = pool_alloconly_create("hard copy rollbacks", 2048);
	rollbacks = NULL;

	custom_flags = mail_custom_flags_list_get(index->custom_flags);

	ret = 1;
	while ((mail = index_messageset_next(ctx)) != NULL) {
		flags = mail->rec->msg_flags;
		if (!index_mailbox_fix_custom_flags(dest, &flags,
						    custom_flags,
						    MAIL_CUSTOM_FLAGS_COUNT)) {
			ret = -1;
			break;
		}

		/* link the file */
		fname = index->lookup_field(index, mail->rec,
					    DATA_FIELD_LOCATION);
		if (fname == NULL) {
			index_set_corrupted(index,
				"Missing location field for record %u",
				mail->rec->uid);
			ret = -1;
			break;
		}

		t_push();
		src_path = t_strconcat(index->mailbox_path, "/cur/",
				       fname, NULL);

		dest_fname = maildir_generate_tmp_filename(&ioloop_timeval);
		dest_fname = maildir_filename_set_flags(dest_fname, flags);
		dest_path = t_strconcat(dest->index->mailbox_path, "/new/",
					dest_fname, NULL);

		if (link(src_path, dest_path) == 0) {
			rb = p_new(pool, struct rollback, 1);
			rb->fname = p_strdup(pool, dest_fname);
			rb->next = rollbacks;
			rollbacks = rb;
		} else {
			if (errno != EXDEV) {
				mail_storage_set_critical(src->box.storage,
					"link(%s, %s) failed: %m",
					src_path, dest_path);
				t_pop();
				ret = -1;
				break;
			}
			t_pop();
			ret = 0;
			break;
		}
		t_pop();
	}

	if (ret <= 0) {
		for (rb = rollbacks; rb != NULL; rb = rb->next) {
			t_push();
			(void)unlink(t_strconcat(dest->index->mailbox_path,
						 "new/", rb->fname, NULL));
			t_pop();
		}
	}

	pool_unref(pool);
	return ret;
}

static int copy_with_hardlinks(struct index_mailbox *src,
			       struct index_mailbox *dest,
			       const char *messageset, int uidset)
{
        struct messageset_context *ctx;
	int ret, ret2;

	if (!index_storage_sync_and_lock(src, TRUE, MAIL_LOCK_SHARED))
		return -1;

	ctx = index_messageset_init(src, messageset, uidset, FALSE);
	ret = hardlink_messageset(ctx, src, dest);
	ret2 = index_messageset_deinit(ctx);
	if (ret2 < 0)
		ret = -1;
	else {
		mail_storage_set_error(src->box.storage,
			"Some of the requested messages no longer exist.");
		ret = -1;
	}

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
