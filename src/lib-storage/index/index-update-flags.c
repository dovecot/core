/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "mail-custom-flags.h"

typedef struct {
	IndexMailbox *ibox;
	MailFlags flags;
	ModifyType modify_type;
	int notify;
} UpdateContext;

static int update_func(MailIndex *index, MailIndexRecord *rec,
		       unsigned int client_seq, unsigned int idx_seq,
		       void *context)
{
	UpdateContext *ctx = context;
	MailFlags flags;
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
		flags = 0;
		i_assert(0);
	}

	if (!index->update_flags(index, rec, idx_seq, flags, FALSE))
		return FALSE;

	if (mail_custom_flags_has_changes(index->custom_flags)) {
		ctx->ibox->sync_callbacks.new_custom_flags(&ctx->ibox->box,
			mail_custom_flags_list_get(index->custom_flags),
			MAIL_CUSTOM_FLAGS_COUNT, ctx->ibox->sync_context);
	}

	if (ctx->notify) {
		if (rec->uid >= index->first_recent_uid)
			flags |= MAIL_RECENT;

                custom_flags = mail_custom_flags_list_get(index->custom_flags);
		ctx->ibox->sync_callbacks.update_flags(&ctx->ibox->box,
						       client_seq, rec->uid,
						       flags, custom_flags,
						       MAIL_CUSTOM_FLAGS_COUNT,
						       ctx->ibox->sync_context);
	}

	return TRUE;
}

int index_storage_update_flags(Mailbox *box, const char *messageset, int uidset,
			       MailFlags flags, const char *custom_flags[],
			       ModifyType modify_type, int notify,
			       int *all_found)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
        UpdateContext ctx;
	int ret;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_storage_sync_index_if_possible(ibox))
		return FALSE;

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_EXCLUSIVE))
		return mail_storage_set_index_error(ibox);

	ctx.ibox = ibox;
	ctx.flags = flags & ~MAIL_RECENT; /* \Recent can't be changed */
	ctx.modify_type = modify_type;
	ctx.notify = notify;

	ret = index_messageset_foreach(ibox, messageset, uidset,
				       update_func, &ctx);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;
	return ret >= 0;
}
