/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "mail-custom-flags.h"

int index_storage_update_flags(struct mail *mail,
			       const struct mail_full_flags *flags,
			       enum modify_type modify_type)
{
	struct index_mail *imail = (struct index_mail *) mail;
	struct index_mailbox *ibox = imail->ibox;
	struct mail_storage *storage = mail->box->storage;
	enum mail_flags modify_flags, new_flags;

	if (mail->box->readonly) {
		if (ibox->sent_readonly_flags_warning)
			return TRUE;
                ibox->sent_readonly_flags_warning = TRUE;

		storage->callbacks->
			notify_no(&ibox->box,
				  "Mailbox is read-only, ignoring flag changes",
				  storage->callback_context);
		return TRUE;
	}

	/* \Recent can't be changed */
	modify_flags = flags->flags & ~MAIL_RECENT;

	if (!index_mailbox_fix_custom_flags(ibox, &modify_flags,
					    flags->custom_flags,
					    flags->custom_flags_count))
		return FALSE;

	switch (modify_type) {
	case MODIFY_ADD:
		new_flags = imail->data.rec->msg_flags | modify_flags;
		break;
	case MODIFY_REMOVE:
		new_flags = imail->data.rec->msg_flags & ~modify_flags;
		break;
	case MODIFY_REPLACE:
		new_flags = modify_flags;
		break;
	default:
		i_unreached();
	}

	if (!ibox->index->update_flags(ibox->index, imail->data.rec,
				       imail->data.idx_seq, new_flags, FALSE))
		return FALSE;

	if (mail_custom_flags_has_changes(ibox->index->custom_flags)) {
		storage->callbacks->new_custom_flags(&ibox->box,
			mail_custom_flags_list_get(ibox->index->custom_flags),
			MAIL_CUSTOM_FLAGS_COUNT, storage->callback_context);
	}

	return TRUE;
}
