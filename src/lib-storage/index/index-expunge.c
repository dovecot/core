/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "index-expunge.h"

static int index_expunge_seek_first(struct index_mailbox *ibox,
				    unsigned int *seq,
				    struct mail_index_record **rec)
{
	struct mail_index_header *hdr;

	i_assert(ibox->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	hdr = ibox->index->get_header(ibox->index);
	if (hdr->deleted_messages_count == 0) {
		/* no deleted messages */
		*seq = 0;
		*rec = NULL;
		return TRUE;
	}

	/* find mails with DELETED flag and expunge them */
	if (hdr->first_deleted_uid_lowwater > 1) {
		*rec = hdr->first_deleted_uid_lowwater >= hdr->next_uid ? NULL :
			ibox->index->lookup_uid_range(ibox->index,
						hdr->first_deleted_uid_lowwater,
						hdr->next_uid-1, seq);
		if (*rec == NULL) {
			mail_storage_set_critical(ibox->box.storage,
				"index header's deleted_messages_count (%u) "
				"or first_deleted_uid_lowwater (%u) "
				"is invalid.", hdr->deleted_messages_count,
				hdr->first_deleted_uid_lowwater);

			/* fsck should be enough to fix it */
			ibox->index->set_flags |= MAIL_INDEX_FLAG_FSCK;
			return FALSE;
		}
	} else {
		*rec = ibox->index->lookup(ibox->index, 1);
		*seq = 1;
	}

	return TRUE;
}

struct mail_expunge_context *
index_storage_expunge_init(struct mailbox *box,
			   enum mail_fetch_field wanted_fields,
			   int expunge_all)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_expunge_context *ctx;

	if (box->is_readonly(box)) {
		box->storage->callbacks->
			notify_no(box, "Mailbox is read-only, ignoring expunge",
				  box->storage->callback_context);
		return i_new(struct mail_expunge_context, 1);
	}

	if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
		return NULL;

	ctx = i_new(struct mail_expunge_context, 1);
	ctx->ibox = ibox;
	ctx->expunge_all = expunge_all;
	index_mail_init(ibox, &ctx->mail, wanted_fields, NULL);

	do {
		if (!index_storage_sync_and_lock(ibox, FALSE, TRUE,
						 MAIL_LOCK_EXCLUSIVE))
			break;

		/* modifylog must be marked synced before expunging
		   anything new */
		if (!index_storage_sync_modifylog(ibox, TRUE))
			break;

		if (expunge_all) {
			ctx->seq = 1;
			ctx->rec = ibox->index->lookup(ibox->index, 1);
		} else {
			if (!index_expunge_seek_first(ibox, &ctx->seq,
						      &ctx->rec))
				break;

			ctx->fetch_next = ctx->rec != NULL &&
				(ctx->rec->msg_flags & MAIL_DELETED) == 0;
		}

		return ctx;
	} while (0);

	(void)index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK);
	i_free(ctx);
	return NULL;
}

int index_storage_expunge_deinit(struct mail_expunge_context *ctx)
{
	int ret = !ctx->failed;

	if (ctx->first_seq != 0) {
		if (!ctx->ibox->index->expunge(ctx->ibox->index,
					       ctx->first_rec, ctx->last_rec,
					       ctx->first_seq, ctx->last_seq,
					       FALSE))
			ret = FALSE;
	}

	if (ctx->ibox != NULL) {
		ctx->ibox->fetch_mail.data.rec = NULL;

		if (!index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK))
			ret = FALSE;
	}

	i_free(ctx);
	return ret;
}

struct mail *index_storage_expunge_fetch_next(struct mail_expunge_context *ctx)
{
	struct mail_index *index = ctx->ibox->index;

	if (ctx->rec == NULL)
		return NULL;

	if (ctx->fetch_next) {
		do {
			ctx->seq++;
			ctx->rec = index->next(index, ctx->rec);
			if (ctx->rec == NULL)
				return NULL;
		} while ((ctx->rec->msg_flags & MAIL_DELETED) == 0 &&
			 !ctx->expunge_all);
	} else {
		ctx->fetch_next = TRUE;
	}

	ctx->mail.expunge_counter = index->expunge_counter;
	ctx->mail.mail.seq = ctx->seq;
	ctx->mail.mail.uid = ctx->rec->uid;

	if (!index_mail_next(&ctx->mail, ctx->rec, ctx->seq)) {
		ctx->failed = TRUE;
		return NULL;
	}

	return &ctx->mail.mail;
}

int index_storage_expunge(struct mail *mail, struct mail_expunge_context *ctx,
			  unsigned int *seq_r, int notify)
{
	struct index_mail *imail = (struct index_mail *) mail;
	struct index_mailbox *ibox = imail->ibox;
	unsigned int seq;

	/* currently we allow expunges only from beginning to end so we can
	   easily update sequence numbers */
	i_assert(ctx->last_seq < ctx->seq);

	seq = mail->seq;
	if (ctx->first_seq != 0)
		seq -= (ctx->last_seq - ctx->first_seq) + 1;
	if (seq_r != NULL) *seq_r = seq;

	if (ctx->first_seq != 0 && ctx->seq != ctx->last_seq+1) {
		if (!ibox->index->expunge(ibox->index,
					  ctx->first_rec, ctx->last_rec,
					  ctx->first_seq, ctx->last_seq, FALSE))
			return FALSE;

		ctx->seq -= (ctx->last_seq - ctx->first_seq) + 1;
		ctx->rec = ibox->index->lookup(ibox->index, ctx->seq);

		ctx->first_seq = 0;
	}

	if (ctx->first_seq == 0) {
		ctx->first_seq = ctx->seq;
		ctx->first_rec = ctx->rec;
	}
	ctx->last_seq = ctx->seq;
	ctx->last_rec = ctx->rec;

	ibox->fetch_mail.data.rec = NULL;

	ibox->synced_messages_count--;
	if (notify && seq <= ibox->synced_messages_count+1) {
		ibox->box.storage->callbacks->
			expunge(&ibox->box, seq,
				ibox->box.storage->callback_context);
	}

	return TRUE;
}
