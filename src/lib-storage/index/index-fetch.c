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

	enum mail_lock_type old_lock;
};

struct mail_fetch_context *
index_storage_fetch_init(struct mailbox *box,
			 enum mail_fetch_field wanted_fields, int update_flags,
			 const char *messageset, int uidset)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_fetch_context *ctx;
	int check_mail;

	ctx = i_new(struct mail_fetch_context, 1);
	ctx->old_lock = ibox->index->lock_type;

	/* need exclusive lock to update the \Seen flags */
	if (update_flags && !box->readonly) {
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return NULL;
	}

	check_mail = (client_workarounds &
		      WORKAROUND_OE6_FETCH_NO_NEWMAIL) == 0;
	if (!index_storage_sync_and_lock(ibox, check_mail, TRUE,
					 MAIL_LOCK_SHARED))
		return NULL;

	ctx->ibox = ibox;
	ctx->index = ibox->index;

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

	if (!index_storage_lock(ctx->ibox, ctx->old_lock))
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
	int ret;

	do {
		msgset_mail = index_messageset_next(ctx->msgset_ctx);
		if (msgset_mail == NULL)
			return NULL;

		ctx->mail.mail.seq = msgset_mail->client_seq;
		ctx->mail.mail.uid = msgset_mail->rec->uid;

		ret = index_mail_next(&ctx->mail, msgset_mail->rec,
				      msgset_mail->idx_seq);
	} while (ret == 0);

	return ret < 0 ? NULL : &ctx->mail.mail;
}

static struct mail *
fetch_record(struct index_mailbox *ibox, struct mail_index_record *rec,
	     unsigned int idx_seq, enum mail_fetch_field wanted_fields)
{
	if (ibox->fetch_mail.pool != NULL)
		index_mail_deinit(&ibox->fetch_mail);

	index_mail_init(ibox, &ibox->fetch_mail, wanted_fields, NULL);
	if (index_mail_next(&ibox->fetch_mail, rec, idx_seq) <= 0)
		return NULL;

	return &ibox->fetch_mail.mail;
}

struct mail *index_storage_fetch_uid(struct mailbox *box, unsigned int uid,
				     enum mail_fetch_field wanted_fields)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_index_record *rec;
	unsigned int seq;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	rec = ibox->index->lookup_uid_range(ibox->index, uid, uid, &seq);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, seq, wanted_fields);
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

	seq -= expunges_before;
	rec = ibox->index->lookup(ibox->index, seq);
	if (rec == NULL)
		return NULL;

	return fetch_record(ibox, rec, seq, wanted_fields);
}
