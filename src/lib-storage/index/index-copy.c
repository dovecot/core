/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"

#include <unistd.h>

static int copy_messageset(struct messageset_context *msgset_ctx,
                           struct mail_save_context *save_ctx,
			   struct index_mailbox *src,
			   struct mailbox *dest)
{
        const struct messageset_mail *mail;
	struct mail_full_flags flags;
	struct istream *input;
	time_t received_date;
	int failed, deleted;

	memset(&flags, 0, sizeof(flags));
	flags.custom_flags =
		mail_custom_flags_list_get(src->index->custom_flags);
	flags.custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;

	while ((mail = index_messageset_next(msgset_ctx)) != NULL) {
		input = src->index->open_mail(src->index, mail->rec,
					      &received_date, &deleted);
		if (input == NULL)
			return FALSE;

		flags.flags = mail->rec->msg_flags;
		failed = !dest->save_next(save_ctx, &flags, received_date,
					  0, input);
		i_stream_unref(input);

		if (failed)
			return FALSE;
	}

	return TRUE;
}

int index_storage_copy(struct mailbox *box, struct mailbox *destbox,
		       const char *messageset, int uidset)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct messageset_context *msgset_ctx;
        struct mail_save_context *save_ctx;
	int ret, ret2, copy_inside_mailbox;

	if (destbox->readonly) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return FALSE;
	}

	copy_inside_mailbox =
		destbox->storage == box->storage &&
		strcmp(destbox->name, box->name) == 0;

	if (copy_inside_mailbox) {
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return FALSE;
	} else {
		if (!index_storage_sync_and_lock(ibox, TRUE, TRUE,
						 MAIL_LOCK_SHARED))
			return FALSE;
	}

	save_ctx = destbox->save_init(destbox, TRUE);
	if (save_ctx == NULL)
		ret = FALSE;
	else {
		/* abort if any of the messages are expunged */
		msgset_ctx = index_messageset_init(ibox, messageset, uidset,
						   FALSE);
		ret = copy_messageset(msgset_ctx, save_ctx, ibox, destbox);
		ret2 = index_messageset_deinit(msgset_ctx);
		if (ret2 < 0)
			ret = FALSE;
		else if (ret2 == 0) {
			mail_storage_set_error(ibox->box.storage,
			     "Some of the requested messages no longer exist.");
			ret = FALSE;
		}

		if (!destbox->save_deinit(save_ctx, !ret))
			ret = FALSE;
	}

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		ret = FALSE;

	return ret;
}
