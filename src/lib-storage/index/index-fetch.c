/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ostream.h"
#include "str.h"
#include "mail-index.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"
#include "index-mail.h"

struct mail_fetch_context {
	struct index_mailbox *ibox;
	struct mail_index *index;

	struct messageset_context *msgset_ctx;
	struct index_mail mail;

	int update_seen;
};

struct mail_fetch_context *
index_storage_fetch_init(struct mailbox *box,
			 enum mail_fetch_field wanted_fields, int *update_seen,
			 const char *messageset, int uidset)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct mail_fetch_context *ctx;

	ctx = i_new(struct mail_fetch_context, 1);

	if (!box->readonly)
		*update_seen = FALSE;

	/* need exclusive lock to update the \Seen flags */
	if (*update_seen) {
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return NULL;
	}

	if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_SHARED))
		return NULL;

	if (*update_seen &&
	    ibox->index->header->messages_count ==
	    ibox->index->header->seen_messages_count) {
		/* if all messages are already seen, there's no point in
		   keeping exclusive lock */
		*update_seen = FALSE;
		(void)index_storage_lock(ibox, MAIL_LOCK_SHARED);
	}

	ctx->ibox = ibox;
	ctx->index = ibox->index;
	ctx->update_seen = *update_seen;

	index_mail_init(ibox, &ctx->mail, wanted_fields, NULL);
	ctx->msgset_ctx = index_messageset_init(ibox, messageset, uidset, TRUE);
	return ctx;
}

int index_storage_fetch_deinit(struct mail_fetch_context *ctx, int *all_found)
{
	int ret;

	ret = index_messageset_deinit(ctx->msgset_ctx);

	if (all_found != NULL)
		*all_found = ret > 0;

	if (!index_storage_lock(ctx->ibox, MAIL_LOCK_UNLOCK))
		ret = -1;

	if (ctx->ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ctx->ibox->fetch_mail);
	index_mail_deinit(&ctx->mail);
	i_free(ctx);
	return ret >= 0;
}

struct mail *index_storage_fetch_next(struct mail_fetch_context *ctx)
{
	const struct messageset_mail *msgset_mail;
	struct mail_index_record *rec;
	int ret;

	do {
		msgset_mail = index_messageset_next(ctx->msgset_ctx);
		if (msgset_mail == NULL)
			return NULL;

		rec = msgset_mail->rec;
		ctx->mail.mail.seen_updated = FALSE;
		if (ctx->update_seen && (rec->msg_flags & MAIL_SEEN) == 0) {
			if (ctx->index->update_flags(ctx->index, rec,
						     msgset_mail->idx_seq,
						     rec->msg_flags | MAIL_SEEN,
						     FALSE))
				ctx->mail.mail.seen_updated = TRUE;
		}

		ctx->mail.mail.seq = msgset_mail->client_seq;
		ctx->mail.mail.uid = rec->uid;

		ret = index_mail_next(&ctx->mail, rec);
	} while (ret == 0);

	return ret < 0 ? NULL : &ctx->mail.mail;
}

static struct mail *
fetch_record(struct index_mailbox *ibox, struct mail_index_record *rec,
	     enum mail_fetch_field wanted_fields)
{
	if (ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ibox->fetch_mail);

	index_mail_init(ibox, &ibox->fetch_mail, wanted_fields, NULL);
	if (index_mail_next(&ibox->fetch_mail, rec) <= 0)
		return NULL;

	return &ibox->fetch_mail.mail;
}

struct mail *index_storage_fetch_uid(struct mailbox *box, unsigned int uid,
				     enum mail_fetch_field wanted_fields)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct mail_index_record *rec;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	rec = ibox->index->lookup_uid_range(ibox->index, uid, uid, NULL);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, wanted_fields);
}

struct mail *index_storage_fetch_seq(struct mailbox *box, unsigned int seq,
				     enum mail_fetch_field wanted_fields)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
        struct mail_index_record *rec;
	unsigned int expunges_before;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	if (mail_modifylog_seq_get_expunges(ibox->index->modifylog, seq, seq,
					    &expunges_before) == NULL)
		return NULL;

	rec = ibox->index->lookup(ibox->index, seq - expunges_before);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, wanted_fields);
}
