/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"

#include <unistd.h>

typedef struct {
	Mailbox *dest;
	const char **custom_flags;
} CopyContext;

static int copy_func(MailIndex *index, MailIndexRecord *rec,
		     unsigned int client_seq __attr_unused__,
		     unsigned int idx_seq __attr_unused__, void *context)
{
	CopyContext *ctx = context;
	IBuffer *inbuf;
	time_t internal_date;
	int failed, deleted;

	inbuf = index->open_mail(index, rec, &internal_date, &deleted);
	if (inbuf == NULL)
		return FALSE;

	/* save it in destination mailbox */
	failed = !ctx->dest->save(ctx->dest, rec->msg_flags,
				  ctx->custom_flags, internal_date, 0,
				  inbuf, inbuf->v_size);

	i_buffer_unref(inbuf);
	return !failed;
}

int index_storage_copy(Mailbox *box, Mailbox *destbox,
		       const char *messageset, int uidset)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
        CopyContext ctx;
	MailLockType lock_type;
	int failed;

	if (destbox->readonly) {
		mail_storage_set_error(box->storage,
				       "Destination mailbox is read-only");
		return FALSE;
	}

	lock_type = destbox->storage == box->storage &&
		strcmp(destbox->name, box->name) == 0 ?
		MAIL_LOCK_EXCLUSIVE : MAIL_LOCK_SHARED;

	if (!ibox->index->sync_and_lock(ibox->index, lock_type, NULL))
		return mail_storage_set_index_error(ibox);

	ctx.custom_flags =
		mail_custom_flags_list_get(ibox->index->custom_flags);
	ctx.dest = destbox;

	failed = index_messageset_foreach(ibox, messageset, uidset,
					  copy_func, &ctx) <= 0;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return !failed;
}
