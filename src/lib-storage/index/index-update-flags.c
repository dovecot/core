/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "mail-messageset.h"

typedef struct {
	Mailbox *box;
	MailFlags flags;
	FlagsFile *flagsfile;
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

	if (rec->uid >= index->first_recent_uid)
		flags |= MAIL_RECENT;

	if (!index->update_flags(index, rec, seq, flags, FALSE))
		return FALSE;

	if (ctx->func != NULL) {
		ctx->func(ctx->box, seq, rec->uid, flags,
			  flags_file_list_get(ctx->flagsfile),
			  ctx->context);
		flags_file_list_unref(ctx->flagsfile);
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
		return mail_storage_set_index_error((IndexMailbox *) box);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_EXCLUSIVE))
		return mail_storage_set_index_error(ibox);

	ctx.box = box;
	ctx.flags = flags & ~MAIL_RECENT; /* \Recent can't be changed */
	ctx.flagsfile = ibox->flagsfile;
	ctx.modify_type = modify_type;
	ctx.func = func;
	ctx.context = context;

	if (uidset) {
		ret = mail_index_uidset_foreach(ibox->index, messageset,
						ibox->synced_messages_count,
						update_func, &ctx);
	} else {
		ret = mail_index_messageset_foreach(ibox->index,
						    messageset,
						    ibox->synced_messages_count,
						    update_func, &ctx);
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || ret == -1)
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;
	return TRUE;
}
