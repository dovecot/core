/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"

#include <unistd.h>

static int copy_messageset(struct messageset_context *ctx,
			   struct index_mailbox *src, struct mailbox *dest)
{
        const struct messageset_mail *mail;
	struct mail_full_flags flags;
	struct istream *input;
	time_t internal_date;
	int failed, deleted;

	memset(&flags, 0, sizeof(flags));
	flags.custom_flags =
		mail_custom_flags_list_get(src->index->custom_flags);
	flags.custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;

	while ((mail = index_messageset_next(ctx)) != NULL) {
		input = src->index->open_mail(src->index, mail->rec,
					      &internal_date, &deleted);
		if (input == NULL) {
			if (deleted)
				continue;
			return FALSE;
		}

		/* save it in destination mailbox */
		flags.flags = mail->rec->msg_flags;
		failed = !dest->save(dest, &flags, internal_date, 0,
				     input, input->v_limit);
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
        struct messageset_context *ctx;
	enum mail_lock_type lock_type;
	int ret, copy_inside_mailbox;

	if (destbox->readonly) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return FALSE;
	}

	copy_inside_mailbox =
		destbox->storage == box->storage &&
		strcmp(destbox->name, box->name) == 0;

	if (copy_inside_mailbox) {
		/* copying inside same mailbox */
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return FALSE;

		/* kludgy.. */
		((struct index_mailbox *) destbox)->delay_save_unlocking = TRUE;

		lock_type = MAIL_LOCK_EXCLUSIVE;
	} else {
		lock_type = MAIL_LOCK_SHARED;
	}

	if (!index_storage_sync_and_lock(ibox, TRUE, lock_type))
		return FALSE;

	ctx = index_messageset_init(ibox, messageset, uidset);
	ret = copy_messageset(ctx, ibox, destbox);
	if (index_messageset_deinit(ctx) < 0)
		ret = FALSE;

	if (copy_inside_mailbox)
		((struct index_mailbox *) destbox)->delay_save_unlocking = TRUE;

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	return ret;
}
