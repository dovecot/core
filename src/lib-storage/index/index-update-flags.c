/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "mail-custom-flags.h"

static int update_messageset(struct messageset_context *ctx,
			     struct index_mailbox *ibox, enum mail_flags flags,
			     enum modify_type modify_type, int notify)
{
	struct mail_storage *storage;
	const struct messageset_mail *mail;
	const char **custom_flags;
	enum mail_flags new_flags;

	storage = ibox->box.storage;
	custom_flags = mail_custom_flags_list_get(ibox->index->custom_flags);

	while ((mail = index_messageset_next(ctx)) != NULL) {
		switch (modify_type) {
		case MODIFY_ADD:
			new_flags = mail->rec->msg_flags | flags;
			break;
		case MODIFY_REMOVE:
			new_flags = mail->rec->msg_flags & ~flags;
			break;
		case MODIFY_REPLACE:
			new_flags = flags;
			break;
		default:
			i_unreached();
		}

		if (!ibox->index->update_flags(ibox->index, mail->rec,
					       mail->idx_seq, new_flags, FALSE))
			return -1;

		if (mail_custom_flags_has_changes(ibox->index->custom_flags)) {
			storage->callbacks->new_custom_flags(&ibox->box,
				custom_flags, MAIL_CUSTOM_FLAGS_COUNT,
				storage->callback_context);
		}

		if (notify) {
			if (mail->rec->uid >= ibox->index->first_recent_uid)
				new_flags |= MAIL_RECENT;

			storage->callbacks->update_flags(&ibox->box,
				mail->client_seq, mail->rec->uid, new_flags,
				custom_flags, MAIL_CUSTOM_FLAGS_COUNT,
				storage->callback_context);
		}
	}

	return 1;
}

int index_storage_update_flags(struct mailbox *box, const char *messageset,
			       int uidset, const struct mail_full_flags *flags,
			       enum modify_type modify_type, int notify,
			       int *all_found)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct messageset_context *ctx;
	enum mail_flags mail_flags;
	int ret, ret2;

	if (box->readonly) {
		box->storage->callbacks->
			notify_no(&ibox->box,
				  "Mailbox is read-only, ignoring store",
				  box->storage->callback_context);
		return TRUE;
	}

	mail_flags = flags->flags;
	if (!index_mailbox_fix_custom_flags(ibox, &mail_flags,
					    flags->custom_flags,
					    flags->custom_flags_count))
		return FALSE;

	if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_UNLOCK))
		return FALSE;

	mail_flags &= ~MAIL_RECENT; /* \Recent can't be changed */

	ctx = index_messageset_init(ibox, messageset, uidset, TRUE);
	ret = update_messageset(ctx, ibox, mail_flags, modify_type, notify);
	ret2 = index_messageset_deinit(ctx);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (all_found != NULL)
		*all_found = ret2 > 0;
	return ret >= 0 && ret2 >= 0;
}
