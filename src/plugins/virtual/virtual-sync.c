/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mail-search-build.h"
#include "virtual-storage.h"

#include <stdlib.h>

struct virtual_sync_mail {
	uint32_t vseq;
	struct virtual_mail_index_record vrec;
};

struct virtual_sync_context {
	struct virtual_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index *index;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	const char *const *kw_all;

	enum mailbox_sync_flags flags;
	uint32_t uid_validity;
	unsigned int expunge_removed:1;
};

static void virtual_sync_set_uidvalidity(struct virtual_sync_context *ctx)
{
	uint32_t uid_validity = ioloop_time;

	mail_index_update_header(ctx->trans,
		offsetof(struct mail_index_header, uid_validity),
		&uid_validity, sizeof(uid_validity), TRUE);
	ctx->uid_validity = uid_validity;
}

static void virtual_sync_external_flags(struct virtual_sync_context *ctx,
					struct virtual_backend_box *bbox,
					uint32_t vseq, uint32_t real_uid)
{
	enum mail_flags flags;
	const char *const *kw_names;
	struct mail_keywords *keywords;

	if (!mail_set_uid(bbox->sync_mail, real_uid))
		i_panic("UID lost unexpectedly");

	/* copy flags */
	flags = mail_get_flags(bbox->sync_mail);
	mail_index_update_flags(ctx->trans, vseq, MODIFY_REPLACE, flags);

	/* copy keywords */
	kw_names = mail_get_keywords(bbox->sync_mail);
	if (kw_names[0] != NULL) {
		keywords = mail_index_keywords_create(ctx->index, kw_names);
		mail_index_update_keywords(ctx->trans, vseq,
					   MODIFY_REPLACE, keywords);
		mail_index_keywords_free(&keywords);
	}
}

static void virtual_sync_external_appends(struct virtual_sync_context *ctx,
					  struct virtual_backend_box *bbox,
					  uint32_t uid1, uint32_t uid2)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_mail_index_record vrec;
	uint32_t uid, vseq;

	vrec.mailbox_id = bbox->mailbox_id;
	for (uid = uid1; uid <= uid2; uid++) {
		mail_index_append(ctx->trans, 0, &vseq);
		vrec.real_uid = uid;
		mail_index_update_ext(ctx->trans, vseq, virtual_ext_id,
				      &vrec, NULL);
		virtual_sync_external_flags(ctx, bbox, vseq, uid);
	}
}

static void
virtual_sync_external_appends_finish_box(struct virtual_sync_context *ctx,
					 struct virtual_backend_box *bbox)
{
	const struct seq_range *seqs;
	unsigned int seqs_count;
	uint32_t first_ruid, last_ruid;

	seqs = array_get(&bbox->uids, &seqs_count);
	while (bbox->sync_iter_idx < seqs_count) {
		/* max(seq1,prev_uid+1)..seq2 contain newly seen UIDs */
		first_ruid = I_MAX(seqs[bbox->sync_iter_idx].seq1,
				   bbox->sync_iter_prev_real_uid + 1);
		last_ruid = seqs[bbox->sync_iter_idx].seq2;

		if (first_ruid <= last_ruid) {
			virtual_sync_external_appends(ctx, bbox,
						      first_ruid, last_ruid);
		}
		bbox->sync_iter_idx++;
	}
}

static void
virtual_sync_external_appends_finish(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;
	uint32_t next_uid;

	next_uid = mail_index_get_header(ctx->sync_view)->next_uid;
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		virtual_sync_external_appends_finish_box(ctx, bboxes[i]);
		mail_index_append_assign_uids(ctx->trans, next_uid, &next_uid);
	}
}

static int virtual_sync_mail_cmp(const void *p1, const void *p2)
{
	const struct virtual_sync_mail *m1 = p1, *m2 = p2;

	if (m1->vrec.mailbox_id < m2->vrec.mailbox_id)
		return -1;
	if (m1->vrec.mailbox_id > m2->vrec.mailbox_id)
		return 1;

	if (m1->vrec.real_uid < m2->vrec.real_uid)
		return -1;
	if (m1->vrec.real_uid > m2->vrec.real_uid)
		return 1;
	/* broken */
	return 0;
}

static void virtual_sync_external(struct virtual_sync_context *ctx)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_backend_box *bbox;
	struct virtual_sync_mail *vmails;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	const struct seq_range *seqs;
	unsigned int i, seqs_count;
	uint32_t vseq, first_ruid, last_ruid, messages;
	bool expunged;

	messages = mail_index_view_get_messages_count(ctx->sync_view);

	/* sort the messages by their backend mailbox and real UID */
	vmails = messages == 0 ? NULL :
		i_new(struct virtual_sync_mail, messages);
	for (vseq = 1; vseq <= messages; vseq++) {
		mail_index_lookup_ext(ctx->sync_view, vseq, virtual_ext_id,
				      &data, &expunged);
		vrec = data;
		vmails[vseq-1].vseq = vseq;
		vmails[vseq-1].vrec = *vrec;
	}
	qsort(vmails, messages, sizeof(*vmails), virtual_sync_mail_cmp);

	bbox = NULL;
	for (i = 0; i < messages; i++) {
		vseq = vmails[i].vseq;
		vrec = &vmails[i].vrec;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
			if (bbox == NULL) {
				/* the entire mailbox is lost */
				mail_index_expunge(ctx->trans, vseq);
				continue;
			}
		}

		seqs = array_get(&bbox->uids, &seqs_count);
		while (bbox->sync_iter_idx < seqs_count) {
			/* max(seq1,prev_uid+1)..min(seq2,uid-1) contain
			   newly seen UIDs */
			first_ruid = I_MAX(seqs[bbox->sync_iter_idx].seq1,
					   bbox->sync_iter_prev_real_uid + 1);
			last_ruid = I_MIN(seqs[bbox->sync_iter_idx].seq2,
					  vrec->real_uid - 1);
			if (first_ruid <= last_ruid) {
				virtual_sync_external_appends(ctx, bbox,
							      first_ruid,
							      last_ruid);
			}
			if (vrec->real_uid <= seqs[bbox->sync_iter_idx].seq2)
				break;
			bbox->sync_iter_idx++;
		}
		if (bbox->sync_iter_idx >= seqs_count ||
		    vrec->real_uid < seqs[bbox->sync_iter_idx].seq1) {
			if (ctx->expunge_removed) {
				mail_index_expunge(ctx->trans, vseq);
				continue;
			}
		}

		/* uid is within seq1..seq2 */
		bbox->sync_iter_prev_real_uid = vrec->real_uid;
		virtual_sync_external_flags(ctx, bbox, vseq, vrec->real_uid);
	}
	i_free(vmails);

	virtual_sync_external_appends_finish(ctx);
}

static void virtual_sync_index_rec(struct virtual_sync_context *ctx,
				   const struct mail_index_sync_rec *sync_rec)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_backend_box *bbox;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	enum mail_flags flags;
	struct mail_keywords *keywords;
	enum modify_type modify_type;
	const char *kw_names[2];
	uint32_t vseq, seq1, seq2;
	bool expunged;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_APPEND:
		/* don't care */
		return;
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
		break;
	}
	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 sync_rec->uid1, sync_rec->uid2,
					 &seq1, &seq2)) {
		/* already expunged, nothing to do. */
		return;
	}

	for (vseq = seq1; vseq <= seq2; vseq++) {
		mail_index_lookup_ext(ctx->sync_view, vseq, virtual_ext_id,
				      &data, &expunged);
		vrec = data;

		bbox = virtual_backend_box_lookup(ctx->mbox, vrec->mailbox_id);
		if (bbox == NULL)
			continue;

		if (!mail_set_uid(bbox->sync_mail, vrec->real_uid))
			i_panic("UID lost unexpectedly");

		switch (sync_rec->type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			mail_expunge(bbox->sync_mail);
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			flags = sync_rec->add_flags & MAIL_FLAGS_NONRECENT;
			if (flags != 0) {
				mail_update_flags(bbox->sync_mail,
						  MODIFY_ADD, flags);
			}
			flags = sync_rec->remove_flags & MAIL_FLAGS_NONRECENT;
			if (flags != 0) {
				mail_update_flags(bbox->sync_mail,
						  MODIFY_REMOVE, flags);
			}
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			kw_names[0] = ctx->kw_all[sync_rec->keyword_idx];
			kw_names[1] = NULL;
			keywords = mailbox_keywords_create_valid(bbox->box,
								 kw_names);

			modify_type = sync_rec->type ==
				MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD ?
				MODIFY_ADD : MODIFY_REMOVE;
			mail_update_keywords(bbox->sync_mail,
					     modify_type, keywords);
			mailbox_keywords_free(bbox->box, &keywords);
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			kw_names[0] = NULL;
			keywords = mailbox_keywords_create_valid(bbox->box,
								 kw_names);
			mail_update_keywords(bbox->sync_mail, MODIFY_REPLACE,
					     keywords);
			mailbox_keywords_free(bbox->box, &keywords);
			break;
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			i_unreached();
		}
	}
}

static void virtual_sync_index(struct virtual_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	const ARRAY_TYPE(keywords) *keywords;
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity != 0)
		ctx->uid_validity = hdr->uid_validity;
	else
		virtual_sync_set_uidvalidity(ctx);

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2)) {
		index_mailbox_set_recent_seq(&ctx->mbox->ibox, ctx->sync_view,
					     seq1, seq2);
	}

	keywords = mail_index_get_keywords(ctx->index);
	ctx->kw_all = array_count(keywords) == 0 ? NULL :
		array_idx(keywords, 0);
	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec))
		virtual_sync_index_rec(ctx, &sync_rec);

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);
}

static int virtual_sync_backend_box(struct virtual_sync_context *ctx,
				    struct virtual_backend_box *bbox)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	enum mailbox_sync_flags sync_flags;
	int ret;

	sync_flags = ctx->flags & (MAILBOX_SYNC_FLAG_FULL_READ |
				   MAILBOX_SYNC_FLAG_FULL_WRITE |
				   MAILBOX_SYNC_FLAG_FAST);
	if (mailbox_sync(bbox->box, sync_flags, 0, NULL) < 0)
		return -1;

	trans = mailbox_transaction_begin(bbox->box, 0);
	mail = mail_alloc(trans, 0, NULL);

	mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);
	search_ctx = mailbox_search_init(trans, bbox->search_args, NULL);

	array_clear(&bbox->uids);
	while (mailbox_search_next(search_ctx, mail) > 0)
		seq_range_array_add(&bbox->uids, 0, mail->uid);
	ret = mailbox_search_deinit(&search_ctx);
	mail_free(&mail);

	mail_search_args_deinit(bbox->search_args);
	(void)mailbox_transaction_commit(&trans);
	return ret;
}

static int virtual_sync_backend_boxes(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	struct mailbox_transaction_context *trans;
	unsigned int i, count;

	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (virtual_sync_backend_box(ctx, bboxes[i]) < 0)
			return -1;

		bboxes[i]->sync_iter_idx = 0;
		bboxes[i]->sync_iter_prev_real_uid = 0;

		i_assert(bboxes[i]->sync_mail == NULL);
		trans = mailbox_transaction_begin(bboxes[i]->box, 0);
		bboxes[i]->sync_mail = mail_alloc(trans, 0, NULL);
	}
	return 0;
}

static void virtual_sync_backend_boxes_finish(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	struct mailbox_transaction_context *trans;
	unsigned int i, count;

	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->sync_mail != NULL) {
			trans = bboxes[i]->sync_mail->transaction;
			mail_free(&bboxes[i]->sync_mail);
			(void)mailbox_transaction_commit(&trans);
		}
	}
}

static int virtual_sync_finish(struct virtual_sync_context *ctx, bool success)
{
	int ret = success ? 0 : -1;

	virtual_sync_backend_boxes_finish(ctx);
	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->ibox);
			ret = -1;
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	i_free(ctx);
	return 0;
}

static int virtual_sync(struct virtual_mailbox *mbox,
			enum mailbox_sync_flags flags)
{
	struct virtual_sync_context *ctx;
	enum mail_index_sync_flags index_sync_flags;
	int ret;

	ctx = i_new(struct virtual_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;
	ctx->index = mbox->ibox.index;
	/* Removed messages are expunged when
	   a) EXPUNGE is used
	   b) Mailbox is being opened (FIX_INCONSISTENT is set) */
	ctx->expunge_removed =
		(ctx->flags & (MAILBOX_SYNC_FLAG_EXPUNGE |
			       MAILBOX_SYNC_FLAG_FIX_INCONSISTENT)) != 0;

	index_sync_flags = MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY |
		MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;
	if (!mbox->ibox.keep_recent)
		index_sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;

	ret = mail_index_sync_begin(ctx->index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans,
				    index_sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		i_free(ctx);
		return ret;
	}

	/* update list of UIDs in mailboxes */
	if (virtual_sync_backend_boxes(ctx) < 0)
		return virtual_sync_finish(ctx, FALSE);

	virtual_sync_index(ctx);
	virtual_sync_external(ctx);
	return virtual_sync_finish(ctx, TRUE);
}

struct mailbox_sync_context *
virtual_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	int ret = 0;

	if (!box->opened)
		index_storage_mailbox_open(&mbox->ibox);

	if (index_mailbox_want_full_sync(&mbox->ibox, flags))
		ret = virtual_sync(mbox, flags);

	return index_mailbox_sync_init(box, flags, ret < 0);
}
