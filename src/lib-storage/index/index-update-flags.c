/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "mail-custom-flags.h"

typedef struct {
	Mailbox *box;
	MailCustomFlags *custom_flags;
	MailFlags flags;
	ModifyType modify_type;
	MailFlagUpdateFunc func;
	void *context;
} UpdateContext;

static int update_func(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, void *context)
{
	UpdateContext *ctx = context;
	MailFlags flags;

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

	if (!index->update_flags(index, rec, seq, flags, FALSE))
		return FALSE;

	if (rec->uid >= index->first_recent_uid)
		flags |= MAIL_RECENT;

	if (ctx->func != NULL) {
		ctx->func(ctx->box, seq, rec->uid, flags,
			  mail_custom_flags_list_get(ctx->custom_flags),
			  ctx->context);
		mail_custom_flags_list_unref(ctx->custom_flags);
	}
	return TRUE;
}

int index_storage_update_flags(Mailbox *box, const char *messageset, int uidset,
			       MailFlags flags, const char *custom_flags[],
			       ModifyType modify_type,
			       MailFlagUpdateFunc func, void *context,
			       int *all_found)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
        UpdateContext ctx;
	int ret;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_EXCLUSIVE))
		return mail_storage_set_index_error(ibox);

	ctx.box = box;
	ctx.flags = flags & ~MAIL_RECENT; /* \Recent can't be changed */
	ctx.custom_flags = ibox->index->custom_flags;
	ctx.modify_type = modify_type;
	ctx.func = func;
	ctx.context = context;

	ret = index_messageset_foreach(ibox, messageset, uidset,
				       update_func, &ctx);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;
	return ret >= 0;
}
