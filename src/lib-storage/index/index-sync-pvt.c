/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "index-sync-private.h"

struct index_mailbox_sync_pvt_context {
	struct mailbox *box;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view_pvt;
	struct mail_index_transaction *trans_pvt;
	struct mail_index_view *view_shared;
};

static int sync_pvt_expunges(struct index_mailbox_sync_pvt_context *ctx)
{
	uint32_t seq_shared, seq_pvt, count_shared, count_pvt;
	uint32_t uid_shared, uid_pvt;

	count_shared = mail_index_view_get_messages_count(ctx->view_shared);
	count_pvt = mail_index_view_get_messages_count(ctx->view_pvt);
	seq_shared = seq_pvt = 1;
	while (seq_pvt <= count_pvt && seq_shared <= count_shared) {
		mail_index_lookup_uid(ctx->view_pvt, seq_pvt, &uid_pvt);
		mail_index_lookup_uid(ctx->view_shared, seq_shared, &uid_shared);
		if (uid_pvt == uid_shared) {
			seq_pvt++;
			seq_shared++;
		} else if (uid_pvt < uid_shared) {
			/* message expunged */
			mail_index_expunge(ctx->trans_pvt, seq_pvt);
			seq_pvt++;
		} else {
			mailbox_set_critical(ctx->box,
				"%s: Message UID=%u unexpectedly inserted to mailbox",
				ctx->box->index_pvt->filepath, uid_shared);
			return -1;
		}
	}
	return 0;
}

static void
sync_pvt_copy_self_flags(struct index_mailbox_sync_pvt_context *ctx,
			 ARRAY_TYPE(keyword_indexes) *keywords,
			 uint32_t seq_old, uint32_t seq_new)
{
	const struct mail_index_record *old_rec;

	old_rec = mail_index_lookup(ctx->view_pvt, seq_old);
	mail_index_lookup_keywords(ctx->view_pvt, seq_old, keywords);
	if (old_rec->flags != 0) {
		mail_index_update_flags(ctx->trans_pvt, seq_new,
					MODIFY_ADD, old_rec->flags);
	}
	if (array_count(keywords) > 0) {
		struct mail_keywords *kw;

		kw = mail_index_keywords_create_from_indexes(ctx->box->index_pvt,
							     keywords);
		mail_index_update_keywords(ctx->trans_pvt, seq_new,
					   MODIFY_ADD, kw);
		mail_index_keywords_unref(&kw);
	}
}

static void
sync_pvt_copy_shared_flags(struct index_mailbox_sync_pvt_context *ctx,
			   uint32_t seq_shared, uint32_t seq_pvt)
{
	const struct mail_index_record *rec;

	rec = mail_index_lookup(ctx->view_shared, seq_shared);
	mail_index_update_flags(ctx->trans_pvt, seq_pvt, MODIFY_ADD,
		rec->flags & mailbox_get_private_flags_mask(ctx->box));
}

static int
index_mailbox_sync_view_refresh(struct index_mailbox_sync_pvt_context *ctx)
{
	/* open a view for the latest version of the index */
	if (mail_index_refresh(ctx->box->index_pvt) < 0 ||
	    mail_index_refresh(ctx->box->index) < 0) {
		mailbox_set_index_error(ctx->box);
		return -1;
	}
	if (ctx->view_shared != NULL)
		mail_index_view_close(&ctx->view_shared);
	ctx->view_shared = mail_index_view_open(ctx->box->index);
	return 0;
}

static int
index_mailbox_sync_open(struct index_mailbox_sync_pvt_context *ctx, bool force)
{
	const struct mail_index_header *hdr_shared, *hdr_pvt;

	if (index_mailbox_sync_view_refresh(ctx) < 0)
		return -1;

	hdr_shared = mail_index_get_header(ctx->view_shared);
	if (hdr_shared->uid_validity == 0 && !force) {
		/* the mailbox hasn't been fully created yet,
		   no need for a private index yet */
		return 0;
	}
	hdr_pvt = mail_index_get_header(ctx->box->view_pvt);
	if (hdr_pvt->next_uid == hdr_shared->next_uid &&
	    hdr_pvt->messages_count == hdr_shared->messages_count && !force) {
		/* no new or expunged mails, don't bother syncing */
		return 0;
	}
	if (mail_index_sync_begin(ctx->box->index_pvt, &ctx->sync_ctx,
				  &ctx->view_pvt, &ctx->trans_pvt, 0) < 0) {
		mailbox_set_index_error(ctx->box);
		return -1;
	}
	/* refresh once more now that we're locked */
	if (index_mailbox_sync_view_refresh(ctx) < 0)
		return -1;
	return 1;
}

int index_mailbox_sync_pvt_init(struct mailbox *box, bool lock,
				struct index_mailbox_sync_pvt_context **ctx_r)
{
	struct index_mailbox_sync_pvt_context *ctx;
	int ret;

	*ctx_r = NULL;

	if ((ret = mailbox_open_index_pvt(box)) <= 0)
		return ret;

	ctx = i_new(struct index_mailbox_sync_pvt_context, 1);
	ctx->box = box;
	if (lock) {
		if (index_mailbox_sync_open(ctx, TRUE) < 0) {
			index_mailbox_sync_pvt_deinit(&ctx);
			return -1;
		}
	}

	*ctx_r = ctx;
	return 1;
}

static int
index_mailbox_sync_pvt_index(struct index_mailbox_sync_pvt_context *ctx,
			     const struct mail_save_private_changes *pvt_changes,
			     unsigned int pvt_changes_count)
{
	const struct mail_index_header *hdr_shared, *hdr_pvt;
	ARRAY_TYPE(keyword_indexes) keywords;
	uint32_t seq_shared, seq_pvt, seq_old_pvt, seq2, count_shared, uid;
	unsigned int pc_idx = 0;
	bool reset = FALSE, preserve_old_flags = FALSE, copy_shared_flags;
	bool initial_index = FALSE;
	int ret;

	if (ctx->sync_ctx == NULL) {
		if ((ret = index_mailbox_sync_open(ctx, FALSE)) <= 0)
			return ret;
	}
	hdr_pvt = mail_index_get_header(ctx->view_pvt);
	hdr_shared = mail_index_get_header(ctx->view_shared);

	if (hdr_shared->uid_validity == hdr_pvt->uid_validity) {
		/* same mailbox. expunge messages from private index that
		   no longer exist. */
		if (sync_pvt_expunges(ctx) < 0) {
			reset = TRUE;
			preserve_old_flags = TRUE;
			t_array_init(&keywords, 32);
		}
	} else if (hdr_pvt->uid_validity == 0 && hdr_pvt->next_uid <= 1) {
		/* creating the initial index - no logging */
		reset = TRUE;
		initial_index = TRUE;
	} else {
		/* mailbox created/recreated */
		reset = TRUE;
		i_info("Mailbox %s UIDVALIDITY changed (%u -> %u), resetting private index",
		       ctx->box->vname, hdr_pvt->uid_validity,
		       hdr_shared->uid_validity);
	}
	/* for public namespaces copy the initial private flags from the shared
	   index. this allows Sieve scripts to set the initial flags. */
	copy_shared_flags =
		ctx->box->list->ns->type == MAIL_NAMESPACE_TYPE_PUBLIC;

	count_shared = mail_index_view_get_messages_count(ctx->view_shared);
	if (!reset) {
		if (!mail_index_lookup_seq_range(ctx->view_shared,
						 hdr_pvt->next_uid,
						 hdr_shared->next_uid,
						 &seq_shared, &seq2)) {
			/* no new messages */
			seq_shared = count_shared+1;
		}
	} else {
		if (!initial_index)
			mail_index_reset(ctx->trans_pvt);
		mail_index_update_header(ctx->trans_pvt,
			offsetof(struct mail_index_header, uid_validity),
			&hdr_shared->uid_validity,
			sizeof(hdr_shared->uid_validity), TRUE);
		seq_shared = 1;
	}

	uid = 0;
	for (; seq_shared <= count_shared; seq_shared++) {
		mail_index_lookup_uid(ctx->view_shared, seq_shared, &uid);
		mail_index_append(ctx->trans_pvt, uid, &seq_pvt);
		if (preserve_old_flags &&
		    mail_index_lookup_seq(ctx->view_pvt, uid, &seq_old_pvt)) {
			/* copy flags from the original private index */
			sync_pvt_copy_self_flags(ctx, &keywords,
						 seq_old_pvt, seq_pvt);
		} else if (copy_shared_flags) {
			sync_pvt_copy_shared_flags(ctx, seq_shared, seq_pvt);
		}

		/* add private flags for the recently saved/copied messages */
		while (pc_idx < pvt_changes_count &&
		       pvt_changes[pc_idx].mailnum <= uid) {
			if (pvt_changes[pc_idx].mailnum == uid) {
				mail_index_update_flags(ctx->trans_pvt, seq_pvt,
					MODIFY_ADD, pvt_changes[pc_idx].flags);
			}
			pc_idx++;
		}
	}

	if (uid < hdr_shared->next_uid) {
		mail_index_update_header(ctx->trans_pvt,
			offsetof(struct mail_index_header, next_uid),
			&hdr_shared->next_uid,
			sizeof(hdr_shared->next_uid), FALSE);
	}

	if ((ret = mail_index_sync_commit(&ctx->sync_ctx)) < 0)
		mailbox_set_index_error(ctx->box);
	return ret;
}

static int
mail_save_private_changes_mailnum_cmp(const struct mail_save_private_changes *c1,
				      const struct mail_save_private_changes *c2)
{
	if (c1->mailnum < c2->mailnum)
		return -1;
	if (c1->mailnum > c2->mailnum)
		return 1;
	return 0;
}

int index_mailbox_sync_pvt_newmails(struct index_mailbox_sync_pvt_context *ctx,
				    struct mailbox_transaction_context *trans)
{
	struct mail_save_private_changes *pvt_changes;
	struct seq_range_iter iter;
	unsigned int i, n, pvt_count;
	uint32_t uid;

	if (index_mailbox_sync_view_refresh(ctx) < 0)
		return -1;

	/* translate mail numbers to UIDs */
	pvt_changes = array_get_modifiable(&trans->pvt_saves, &pvt_count);

	n = i = 0;
	seq_range_array_iter_init(&iter, &trans->changes->saved_uids);
	while (seq_range_array_iter_nth(&iter, n, &uid)) {
		if (pvt_changes[i].mailnum == n) {
			pvt_changes[i].mailnum = uid;
			i++;
		}
		n++;
	}
	/* sort the changes by UID */
	array_sort(&trans->pvt_saves, mail_save_private_changes_mailnum_cmp);

	/* add new mails to the private index with the private flags */
	return index_mailbox_sync_pvt_index(ctx, pvt_changes, pvt_count);
}

int index_mailbox_sync_pvt_view(struct index_mailbox_sync_pvt_context *ctx,
				ARRAY_TYPE(seq_range) *flag_updates,
				ARRAY_TYPE(seq_range) *hidden_updates)
{
	struct mail_index_view_sync_ctx *view_sync_ctx;
	struct mail_index_view_sync_rec sync_rec;
	uint32_t seq1, seq2;
	bool delayed_expunges;

	/* sync private index against shared index by adding/removing mails */
	if (index_mailbox_sync_pvt_index(ctx, NULL, 0) < 0)
		return -1;

	/* sync the private view */
	view_sync_ctx = mail_index_view_sync_begin(ctx->box->view_pvt, 0);
	while (mail_index_view_sync_next(view_sync_ctx, &sync_rec)) {
		if (sync_rec.type != MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS)
			continue;

		/* *_updates contains ctx->box->view sequences (not view_pvt
		   sequences) */
		if (mail_index_lookup_seq_range(ctx->box->view,
						sync_rec.uid1, sync_rec.uid2,
						&seq1, &seq2)) {
			if (!sync_rec.hidden) {
				seq_range_array_add_range(flag_updates,
							  seq1, seq2);
			} else {
				seq_range_array_add_range(hidden_updates,
							  seq1, seq2);
			}
		}
	}
	if (mail_index_view_sync_commit(&view_sync_ctx, &delayed_expunges) < 0)
		return -1;
	return 0;
}

void index_mailbox_sync_pvt_deinit(struct index_mailbox_sync_pvt_context **_ctx)
{
	struct index_mailbox_sync_pvt_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->sync_ctx != NULL)
		mail_index_sync_rollback(&ctx->sync_ctx);
	if (ctx->view_shared != NULL)
		mail_index_view_close(&ctx->view_shared);
	i_free(ctx);
}
