/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "mail-custom-flags.h"

struct update_context {
	struct index_mailbox *ibox;
	enum mail_flags flags;
	enum modify_type modify_type;
	int notify;
};

static int update_func(struct mail_index *index, struct mail_index_record *rec,
		       unsigned int client_seq, unsigned int idx_seq,
		       void *context)
{
	struct update_context *ctx = context;
	struct mail_storage *storage;
	enum mail_flags flags;
	const char **custom_flags;

	switch (ctx->modify_type) {
	case MODIFY_ADD:
		flags = rec->msg_flags | ctx->flags;
		break;
	case MODIFY_REMOVE:
		flags = rec->msg_flags & ~ctx->flags;
		break;
	case MODIFY_REPLACE:
		flags = ctx->flags;
		break;
	default:
                i_unreached();
	}

	if (!index->update_flags(index, rec, idx_seq, flags, FALSE))
		return FALSE;

	storage = ctx->ibox->box.storage;
	if (mail_custom_flags_has_changes(index->custom_flags)) {
		storage->callbacks->new_custom_flags(&ctx->ibox->box,
			mail_custom_flags_list_get(index->custom_flags),
			MAIL_CUSTOM_FLAGS_COUNT, storage->callback_context);
	}

	if (ctx->notify) {
		if (rec->uid >= index->first_recent_uid)
			flags |= MAIL_RECENT;

                custom_flags = mail_custom_flags_list_get(index->custom_flags);
		storage->callbacks->update_flags(&ctx->ibox->box,
						 client_seq, rec->uid,
						 flags, custom_flags,
						 MAIL_CUSTOM_FLAGS_COUNT,
						 storage->callback_context);
	}

	return TRUE;
}

int index_storage_update_flags(struct mailbox *box,
			       const char *messageset, int uidset,
			       enum mail_flags flags,
			       const char *custom_flags[],
			       enum modify_type modify_type, int notify,
			       int *all_found)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct update_context ctx;
	int ret;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return FALSE;

	if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_UNLOCK))
		return FALSE;

	ctx.ibox = ibox;
	ctx.flags = flags & ~MAIL_RECENT; /* \Recent can't be changed */
	ctx.modify_type = modify_type;
	ctx.notify = notify;

	ret = index_messageset_foreach(ibox, messageset, uidset,
				       update_func, &ctx);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (all_found != NULL)
		*all_found = ret == 1;
	return ret >= 0;
}
