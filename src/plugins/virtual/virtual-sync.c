/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "ioloop.h"
#include "str.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-search-result-private.h"
#include "index-sync-private.h"
#include "index-search-result.h"
#include "virtual-storage.h"

#include <stdlib.h>

struct virtual_add_record {
	struct virtual_mail_index_record rec;
	time_t received_date;
};

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

	/* messages expunged within this sync */
	ARRAY_TYPE(seq_range) sync_expunges;

	ARRAY_DEFINE(all_adds, struct virtual_add_record);
	enum mailbox_sync_flags flags;
	uint32_t uid_validity;

	unsigned int ext_header_changed:1;
	unsigned int ext_header_rewrite:1;
	unsigned int expunge_removed:1;
	unsigned int index_broken:1;
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

	if (!mail_set_uid(bbox->sync_mail, real_uid)) {
		i_panic("UID %u lost unexpectedly from %s",
			real_uid, bbox->box->name);
	}

	/* copy flags */
	flags = mail_get_flags(bbox->sync_mail);
	mail_index_update_flags(ctx->trans, vseq, MODIFY_REPLACE, flags);

	/* copy keywords */
	kw_names = mail_get_keywords(bbox->sync_mail);
	keywords = mail_index_keywords_create(ctx->index, kw_names);
	mail_index_update_keywords(ctx->trans, vseq, MODIFY_REPLACE, keywords);
	mail_index_keywords_unref(&keywords);
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

static void
virtual_backend_box_sync_mail_set(struct virtual_backend_box *bbox)
{
	struct mailbox_transaction_context *trans;

	if (bbox->sync_mail == NULL) {
		trans = mailbox_transaction_begin(bbox->box, 0);
		bbox->sync_mail = mail_alloc(trans, 0, NULL);
	}
}

static void
virtual_backend_box_sync_mail_unset(struct virtual_backend_box *bbox)
{
	struct mailbox_transaction_context *trans;

	if (bbox->sync_mail != NULL) {
		trans = bbox->sync_mail->transaction;
		mail_free(&bbox->sync_mail);
		(void)mailbox_transaction_commit(&trans);
	}
}

static int bbox_mailbox_id_cmp(struct virtual_backend_box *const *b1,
			       struct virtual_backend_box *const *b2)
{
	if ((*b1)->mailbox_id < (*b2)->mailbox_id)
		return -1;
	if ((*b1)->mailbox_id > (*b2)->mailbox_id)
		return 1;
	return 0;
}

static int
virtual_sync_get_backend_box(struct virtual_sync_context *ctx, const char *name,
			     struct virtual_backend_box **bbox_r)
{
	*bbox_r = virtual_backend_box_lookup_name(ctx->mbox, name);
	if (*bbox_r != NULL || !ctx->mbox->sync_initialized)
		return 0;

	/* another process just added a new mailbox.
	   we can't handle this currently. */
	ctx->mbox->inconsistent = TRUE;
	mail_storage_set_error(ctx->mbox->box.storage, MAIL_ERROR_TEMP,
		"Backend mailbox added by another session. "
		"Reopen the virtual mailbox.");
	return -1;
}

static int virtual_sync_ext_header_read(struct virtual_sync_context *ctx)
{
	const struct virtual_mail_index_header *ext_hdr;
	const struct mail_index_header *hdr;
	const struct virtual_mail_index_mailbox_record *mailboxes;
	struct virtual_backend_box *bbox, **bboxes;
	const void *ext_data;
	size_t ext_size;
	unsigned int i, count, ext_name_offset, ext_mailbox_count;
	uint32_t prev_mailbox_id;
	int ret = 1;

	hdr = mail_index_get_header(ctx->sync_view);
	mail_index_get_header_ext(ctx->sync_view, ctx->mbox->virtual_ext_id,
				  &ext_data, &ext_size);
	ext_hdr = ext_data;
	if (ctx->mbox->sync_initialized &&
	    ctx->mbox->prev_uid_validity == hdr->uid_validity &&
	    ext_size >= sizeof(*ext_hdr) &&
	    ctx->mbox->prev_change_counter == ext_hdr->change_counter) {
		/* fully refreshed */
		return 1;
	}

	ctx->mbox->prev_uid_validity = hdr->uid_validity;
	if (ext_hdr == NULL ||
	    ctx->mbox->search_args_crc32 != ext_hdr->search_args_crc32) {
		mailboxes = NULL;
		ext_name_offset = 0;
		ext_mailbox_count = 0;
	} else {
		ctx->mbox->prev_change_counter = ext_hdr->change_counter;
		mailboxes = (const void *)(ext_hdr + 1);
		ext_name_offset = sizeof(*ext_hdr) +
			ext_hdr->mailbox_count * sizeof(*mailboxes);
		if (ext_name_offset >= ext_size ||
		    ext_hdr->mailbox_count > INT_MAX/sizeof(*mailboxes)) {
			i_error("virtual index %s: Broken mailbox_count header",
				ctx->mbox->box.path);
			ctx->index_broken = TRUE;
			ext_mailbox_count = 0;
			ret = 0;
		} else {
			ext_mailbox_count = ext_hdr->mailbox_count;
		}
	}

	/* update mailbox backends */
	prev_mailbox_id = 0;
	for (i = 0; i < ext_mailbox_count; i++) {
		if (mailboxes[i].id > ext_hdr->highest_mailbox_id ||
		    mailboxes[i].id <= prev_mailbox_id) {
			i_error("virtual index %s: Broken mailbox id",
				ctx->mbox->box.path);
			break;
		}
		if (mailboxes[i].name_len == 0 ||
		    mailboxes[i].name_len > ext_size) {
			i_error("virtual index %s: Broken mailbox name_len",
				ctx->mbox->box.path);
			break;
		}
		if (ext_name_offset + mailboxes[i].name_len > ext_size) {
			i_error("virtual index %s: Broken mailbox list",
				ctx->mbox->box.path);
			break;
		}
		T_BEGIN {
			const unsigned char *nameptr;
			const char *name;

			nameptr = CONST_PTR_OFFSET(ext_data, ext_name_offset);
			name = t_strndup(nameptr, mailboxes[i].name_len);
			if (virtual_sync_get_backend_box(ctx, name, &bbox) < 0)
				ret = -1;
		} T_END;

		if (bbox == NULL) {
			if (ret < 0)
				return -1;
			/* mailbox no longer exists. */
			ret = 0;
		} else {
			bbox->mailbox_id = mailboxes[i].id;
			bbox->sync_uid_validity = mailboxes[i].uid_validity;
			bbox->ondisk_highest_modseq =
				bbox->sync_highest_modseq =
				mailboxes[i].highest_modseq;
			bbox->sync_next_uid = mailboxes[i].next_uid;
			bbox->sync_mailbox_idx = i;
		}
		ext_name_offset += mailboxes[i].name_len;
		prev_mailbox_id = mailboxes[i].id;
	}
	if (i < ext_mailbox_count) {
		ctx->index_broken = TRUE;
		ret = 0;
	}
	ctx->mbox->highest_mailbox_id = ext_hdr == NULL ? 0 :
		ext_hdr->highest_mailbox_id;
	ctx->mbox->sync_initialized = TRUE;

	/* assign new mailbox IDs if any are missing */
	bboxes = array_get_modifiable(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->mailbox_id == 0) {
			bboxes[i]->mailbox_id = ++ctx->mbox->highest_mailbox_id;
			ret = 0;
		}
	}
	/* sort the backend mailboxes by mailbox_id. */
	array_sort(&ctx->mbox->backend_boxes, bbox_mailbox_id_cmp);
	return ret;
}

static void virtual_sync_ext_header_rewrite(struct virtual_sync_context *ctx)
{
	struct virtual_mail_index_header ext_hdr;
	struct virtual_mail_index_mailbox_record mailbox;
	struct virtual_backend_box **bboxes;
	buffer_t *buf;
	const void *ext_data;
	size_t ext_size;
	unsigned int i, mailbox_pos, name_pos, count;

	bboxes = array_get_modifiable(&ctx->mbox->backend_boxes, &count);
	mailbox_pos = sizeof(ext_hdr);
	name_pos = mailbox_pos + sizeof(mailbox) * count;

	memset(&ext_hdr, 0, sizeof(ext_hdr));
	memset(&mailbox, 0, sizeof(mailbox));

	ext_hdr.change_counter = ++ctx->mbox->prev_change_counter;
	ext_hdr.mailbox_count = count;
	ext_hdr.highest_mailbox_id = ctx->mbox->highest_mailbox_id;
	ext_hdr.search_args_crc32 = ctx->mbox->search_args_crc32;

	buf = buffer_create_dynamic(pool_datastack_create(), name_pos + 256);
	buffer_append(buf, &ext_hdr, sizeof(ext_hdr));

	for (i = 0; i < count; i++) {
		i_assert(i == 0 ||
			 bboxes[i]->mailbox_id > bboxes[i-1]->mailbox_id);

		bboxes[i]->sync_mailbox_idx = i;
		mailbox.id = bboxes[i]->mailbox_id;
		mailbox.name_len = strlen(bboxes[i]->name);
		mailbox.uid_validity = bboxes[i]->sync_uid_validity;
		mailbox.highest_modseq = bboxes[i]->ondisk_highest_modseq;
		mailbox.next_uid = bboxes[i]->sync_next_uid;
		buffer_write(buf, mailbox_pos, &mailbox, sizeof(mailbox));
		buffer_write(buf, name_pos, bboxes[i]->name, mailbox.name_len);

		mailbox_pos += sizeof(mailbox);
		name_pos += mailbox.name_len;
	}
	i_assert(buf->used == name_pos);

	mail_index_get_header_ext(ctx->sync_view, ctx->mbox->virtual_ext_id,
				  &ext_data, &ext_size);
	if (ext_size < name_pos) {
		mail_index_ext_resize(ctx->trans, ctx->mbox->virtual_ext_id,
				      name_pos,
				      sizeof(struct virtual_mail_index_record),
				      sizeof(uint32_t));
	}
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext_id,
				     0, buf->data, name_pos);
}

static void virtual_sync_ext_header_update(struct virtual_sync_context *ctx)
{
	struct virtual_mail_index_header ext_hdr;

	if (!ctx->ext_header_changed)
		return;

	/* we changed something - update the change counter in header */
	ext_hdr.change_counter = ++ctx->mbox->prev_change_counter;
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext_id,
		offsetof(struct virtual_mail_index_header, change_counter),
		&ext_hdr.change_counter, sizeof(ext_hdr.change_counter));
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

		virtual_backend_box_sync_mail_set(bbox);
		if (!mail_set_uid(bbox->sync_mail, vrec->real_uid)) {
			/* message is already expunged from backend mailbox. */
			continue;
		}

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
			mailbox_keywords_unref(bbox->box, &keywords);
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			kw_names[0] = NULL;
			keywords = mailbox_keywords_create_valid(bbox->box,
								 kw_names);
			mail_update_keywords(bbox->sync_mail, MODIFY_REPLACE,
					     keywords);
			mailbox_keywords_unref(bbox->box, &keywords);
			break;
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			i_unreached();
		}
	}
}

static void virtual_sync_index_changes(struct virtual_sync_context *ctx)
{
	const ARRAY_TYPE(keywords) *keywords;
	struct mail_index_sync_rec sync_rec;

	keywords = mail_index_get_keywords(ctx->index);
	ctx->kw_all = array_count(keywords) == 0 ? NULL :
		array_idx(keywords, 0);
	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec))
		virtual_sync_index_rec(ctx, &sync_rec);
}

static void virtual_sync_index_finish(struct virtual_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->box;
	const struct mail_index_header *hdr;
	uint32_t seq1, seq2;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity != 0)
		ctx->uid_validity = hdr->uid_validity;
	else
		virtual_sync_set_uidvalidity(ctx);

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2)) {
		index_mailbox_set_recent_seq(&ctx->mbox->box, ctx->sync_view,
					     seq1, seq2);
	}
	if (ctx->ext_header_rewrite) {
		/* entire mailbox list needs to be rewritten */
		virtual_sync_ext_header_rewrite(ctx);
	} else {
		/* update only changed parts in the header */
		virtual_sync_ext_header_update(ctx);
	}

	if (box->v.sync_notify != NULL)
		box->v.sync_notify(box, 0, 0);
}

static int virtual_sync_backend_box_init(struct virtual_backend_box *bbox)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct virtual_backend_uidmap uidmap;
	enum mailbox_search_result_flags result_flags;
	int ret;

	trans = mailbox_transaction_begin(bbox->box, 0);
	mail = mail_alloc(trans, 0, NULL);

	search_ctx = mailbox_search_init(trans, bbox->search_args, NULL);

	/* save the result and keep it updated */
	result_flags = MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
		MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC;
	bbox->search_result =
		mailbox_search_result_save(search_ctx, result_flags);

	/* add the found UIDs to uidmap. virtual_uid gets assigned later. */
	memset(&uidmap, 0, sizeof(uidmap));
	array_clear(&bbox->uids);
	while (mailbox_search_next(search_ctx, mail)) {
		uidmap.real_uid = mail->uid;
		array_append(&bbox->uids, &uidmap, 1);
	}

	ret = mailbox_search_deinit(&search_ctx);
	mail_free(&mail);

	(void)mailbox_transaction_commit(&trans);
	return ret;
}

static int
virtual_backend_uidmap_bsearch_cmp(const uint32_t *uidp,
				   const struct virtual_backend_uidmap *uidmap)
{
	return *uidp < uidmap->real_uid ? -1 :
		(*uidp > uidmap->real_uid ? 1 : 0);
}

static void
virtual_sync_mailbox_box_remove(struct virtual_sync_context *ctx,
				struct virtual_backend_box *bbox,
				const ARRAY_TYPE(seq_range) *removed_uids)
{
	const struct seq_range *uids;
	struct virtual_backend_uidmap *uidmap;
	unsigned int i, src, dest, uid_count, rec_count;
	uint32_t uid, vseq;

	uids = array_get(removed_uids, &uid_count);
	if (uid_count == 0)
		return;

	/* everything in removed_uids should exist in bbox->uids */
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	i_assert(rec_count >= uid_count);

	/* find the first uidmap record to be removed */
	if (!array_bsearch_insert_pos(&bbox->uids, &uids[0].seq1,
				      virtual_backend_uidmap_bsearch_cmp, &src))
		i_unreached();

	/* remove the unwanted messages */
	dest = src;
	for (i = 0; i < uid_count; i++) {
		uid = uids[i].seq1;
		while (uidmap[src].real_uid != uid) {
			uidmap[dest++] = uidmap[src++];
			i_assert(src < rec_count);
		}

		for (; uid <= uids[i].seq2; uid++, src++) {
			i_assert(src < rec_count);
			i_assert(uidmap[src].real_uid == uid);
			if (mail_index_lookup_seq(ctx->sync_view,
						  uidmap[src].virtual_uid,
						  &vseq))
				mail_index_expunge(ctx->trans, vseq);
		}
	}
	array_delete(&bbox->uids, dest, src - dest);
}

static void
virtual_sync_mailbox_box_add(struct virtual_sync_context *ctx,
			     struct virtual_backend_box *bbox,
			     const ARRAY_TYPE(seq_range) *added_uids_arr)
{
	const struct seq_range *added_uids;
	struct virtual_backend_uidmap *uidmap;
	struct virtual_add_record rec;
	unsigned int i, src, dest, uid_count, add_count, rec_count;
	uint32_t add_uid;

	added_uids = array_get(added_uids_arr, &uid_count);
	if (uid_count == 0)
		return;
	add_count = seq_range_count(added_uids_arr);

	/* none of added_uids should exist in bbox->uids. find the position
	   of the first inserted index. */
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	if (rec_count == 0 ||
	    added_uids[0].seq1 > uidmap[rec_count-1].real_uid) {
		/* fast path: usually messages are appended */
		dest = rec_count;
	} else if (array_bsearch_insert_pos(&bbox->uids, &added_uids[0].seq1,
					    virtual_backend_uidmap_bsearch_cmp,
					    &dest))
		i_unreached();

	/* make space for all added UIDs. */
	if (rec_count == dest)
		array_idx_clear(&bbox->uids, dest + add_count-1);
	else {
		array_copy(&bbox->uids.arr, dest + add_count,
			   &bbox->uids.arr, dest, rec_count - dest);
	}
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	src = dest + add_count;

	/* add/move the UIDs to their correct positions */
	memset(&rec, 0, sizeof(rec));
	rec.rec.mailbox_id = bbox->mailbox_id;
	for (i = 0; i < uid_count; i++) {
		add_uid = added_uids[i].seq1;
		while (src < rec_count && uidmap[src].real_uid < add_uid)
			uidmap[dest++] = uidmap[src++];

		for (; add_uid <= added_uids[i].seq2; add_uid++, dest++) {
			i_assert(dest < rec_count);

			uidmap[dest].real_uid = add_uid;
			uidmap[dest].virtual_uid = 0;

			if (ctx->mbox->uids_mapped) {
				rec.rec.real_uid = add_uid;
				array_append(&ctx->all_adds, &rec, 1);
			}
		}
	}
}

static int virtual_backend_uidmap_cmp(const struct virtual_backend_uidmap *u1,
				      const struct virtual_backend_uidmap *u2)
{
	if (u1->real_uid < u2->real_uid)
		return -1;
	if (u1->real_uid > u2->real_uid)
		return 1;
	return 0;
}

static void virtual_sync_bbox_uids_sort(struct virtual_backend_box *bbox)
{
	/* the uidmap must be sorted by real_uids */
	array_sort(&bbox->uids, virtual_backend_uidmap_cmp);
	bbox->uids_nonsorted = FALSE;
}

static void virtual_sync_backend_boxes_sort_uids(struct virtual_mailbox *mbox)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->uids_nonsorted)
			virtual_sync_bbox_uids_sort(bboxes[i]);
	}
}

static void
virtual_sync_backend_handle_old_vmsgs(struct virtual_sync_context *ctx,
				      struct virtual_backend_box *bbox,
				      struct mail_search_result *result)
{
	const struct virtual_mail_index_record *vrec;
	struct virtual_backend_uidmap uidmap;
	const void *data;
	uint32_t seq, vseq, vuid, messages;
	bool expunged;

	/* add the currently existing UIDs to uidmap. remember the messages
	   that were already expunged */
	memset(&uidmap, 0, sizeof(uidmap));
	array_clear(&bbox->uids);

	messages = mail_index_view_get_messages_count(ctx->sync_view);
	for (vseq = 1; vseq <= messages; vseq++) {
		mail_index_lookup_uid(ctx->sync_view, vseq, &vuid);
		mail_index_lookup_ext(ctx->sync_view, vseq,
				      ctx->mbox->virtual_ext_id,
				      &data, &expunged);
		vrec = data;
		if (vrec->mailbox_id == bbox->mailbox_id) {
			uidmap.real_uid = vrec->real_uid;
			uidmap.virtual_uid = vuid;
			array_append(&bbox->uids, &uidmap, 1);

			if (mail_index_lookup_seq(bbox->box->view,
						  vrec->real_uid, &seq)) {
				seq_range_array_add(&result->uids, 0,
						    vrec->real_uid);
			} else {
				seq_range_array_add(&result->removed_uids, 0,
						    vrec->real_uid);
			}
		}
	}

	virtual_sync_bbox_uids_sort(bbox);
}

static int virtual_sync_backend_box_continue(struct virtual_sync_context *ctx,
					     struct virtual_backend_box *bbox)
{
	const enum mailbox_search_result_flags result_flags =
		MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
		MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC;
	struct mail_index_view *view = bbox->box->view;
	struct mail_search_result *result;
	ARRAY_TYPE(seq_range) removed_uids, added_uids, flag_update_uids;
	uint64_t modseq, old_highest_modseq;
	uint32_t seq, uid, old_msg_count;

	/* initialize the search result from all the existing messages in
	   virtual index. */
	result = mailbox_search_result_alloc(bbox->box, bbox->search_args,
					     result_flags);
	mailbox_search_result_initial_done(result);
	virtual_sync_backend_handle_old_vmsgs(ctx, bbox, result);

	/* get list of changed old messages (messages already once seen by
	   virtual index), based on modseq changes. (we'll assume all modseq
	   changes are due to flag changes, which may not be true in future) */
	if (bbox->sync_next_uid <= 1 ||
	    !mail_index_lookup_seq_range(view, 1, bbox->sync_next_uid-1,
					 &seq, &old_msg_count))
		old_msg_count = 0;
	old_highest_modseq = mail_index_modseq_get_highest(view);

	t_array_init(&flag_update_uids, I_MIN(128, old_msg_count));
	if (bbox->sync_highest_modseq < old_highest_modseq) {
		for (seq = 1; seq <= old_msg_count; seq++) {
			modseq = mail_index_modseq_lookup(view, seq);
			if (modseq > bbox->sync_highest_modseq) {
				mail_index_lookup_uid(view, seq, &uid);
				seq_range_array_add(&flag_update_uids, 0, uid);
			}
		}
	}

	/* update the search result based on the flag changes and
	   new messages */
	if (index_search_result_update_flags(result, &flag_update_uids) < 0 ||
	    index_search_result_update_appends(result, old_msg_count) < 0) {
		mailbox_search_result_free(&result);
		return -1;
	}

	t_array_init(&removed_uids, 128);
	t_array_init(&added_uids, 128);
	mailbox_search_result_sync(result, &removed_uids, &added_uids);
	virtual_sync_mailbox_box_remove(ctx, bbox, &removed_uids);
	virtual_sync_mailbox_box_add(ctx, bbox, &added_uids);

	bbox->search_result = result;
	return 0;
}

static void virtual_sync_drop_existing(struct virtual_backend_box *bbox,
				       ARRAY_TYPE(seq_range) *added_uids)
{
	ARRAY_TYPE(seq_range) drop_uids;
	const struct virtual_backend_uidmap *uidmap;
	struct seq_range_iter iter;
	unsigned int i, n = 0, count;
	uint32_t add_uid;

	seq_range_array_iter_init(&iter, added_uids);
	if (!seq_range_array_iter_nth(&iter, n++, &add_uid))
		return;

	(void)array_bsearch_insert_pos(&bbox->uids, &add_uid,
				       virtual_backend_uidmap_bsearch_cmp, &i);

	uidmap = array_get_modifiable(&bbox->uids, &count);
	if (i == count)
		return;

	t_array_init(&drop_uids, array_count(added_uids));
	for (; i < count; ) {
		if (uidmap[i].real_uid < add_uid) {
			i++;
			continue;
		}
		if (uidmap[i].real_uid == add_uid) {
			seq_range_array_add(&drop_uids, 0, add_uid);
			i++;
		}
		if (!seq_range_array_iter_nth(&iter, n++, &add_uid))
			break;
	}
	seq_range_array_remove_seq_range(added_uids, &drop_uids);
}

static void virtual_sync_drop_nonexistent(struct virtual_backend_box *bbox,
					  ARRAY_TYPE(seq_range) *removed_uids)
{
	ARRAY_TYPE(seq_range) drop_uids;
	const struct virtual_backend_uidmap *uidmap;
	struct seq_range_iter iter;
	unsigned int i, n = 0, count;
	uint32_t remove_uid;
	bool iter_done = FALSE;

	seq_range_array_iter_init(&iter, removed_uids);
	if (!seq_range_array_iter_nth(&iter, n++, &remove_uid))
		return;

	(void)array_bsearch_insert_pos(&bbox->uids, &remove_uid,
				       virtual_backend_uidmap_bsearch_cmp, &i);

	t_array_init(&drop_uids, array_count(removed_uids)); iter_done = FALSE;
	uidmap = array_get_modifiable(&bbox->uids, &count);
	for (; i < count; ) {
		if (uidmap[i].real_uid < remove_uid) {
			i++;
			continue;
		}
		if (uidmap[i].real_uid != remove_uid)
			seq_range_array_add(&drop_uids, 0, remove_uid);
		else
			i++;
		if (!seq_range_array_iter_nth(&iter, n++, &remove_uid)) {
			iter_done = TRUE;
			break;
		}
	}
	if (!iter_done) {
		do {
			seq_range_array_add(&drop_uids, 0, remove_uid);
		} while (seq_range_array_iter_nth(&iter, n++, &remove_uid));
	}
	seq_range_array_remove_seq_range(removed_uids, &drop_uids);
}

static void virtual_sync_mailbox_box_update(struct virtual_sync_context *ctx,
					    struct virtual_backend_box *bbox)
{
	ARRAY_TYPE(seq_range) removed_uids, added_uids, temp_uids;
	unsigned int count1, count2;

	t_array_init(&removed_uids, 128);
	t_array_init(&added_uids, 128);

	mailbox_search_result_sync(bbox->search_result,
				   &removed_uids, &added_uids);
	if (array_is_created(&bbox->sync_outside_expunges)) {
		seq_range_array_remove_seq_range(&bbox->sync_outside_expunges,
						 &added_uids);
		seq_range_array_merge(&removed_uids,
				      &bbox->sync_outside_expunges);
		array_clear(&bbox->sync_outside_expunges);
	}

	virtual_sync_drop_existing(bbox, &added_uids);
	virtual_sync_drop_nonexistent(bbox, &removed_uids);

	/* if any of the pending removes came back, we don't want to expunge
	   them anymore. also since they already exist, remove them from
	   added_uids. */
	count1 = array_count(&bbox->sync_pending_removes);
	count2 = array_count(&added_uids);
	if (count1 > 0 && count2 > 0) {
		t_array_init(&temp_uids, count1);
		array_append_array(&temp_uids, &bbox->sync_pending_removes);
		if (seq_range_array_remove_seq_range(
				&bbox->sync_pending_removes, &added_uids) > 0) {
			seq_range_array_remove_seq_range(&added_uids,
							 &temp_uids);
		}
	}

	if (!ctx->expunge_removed) {
		/* delay removing messages that don't match the search
		   criteria, but don't delay removing expunged messages */
		if (array_count(&ctx->sync_expunges) > 0) {
			seq_range_array_remove_seq_range(&bbox->sync_pending_removes,
							 &ctx->sync_expunges);
			seq_range_array_remove_seq_range(&removed_uids,
							 &ctx->sync_expunges);
			virtual_sync_mailbox_box_remove(ctx, bbox,
							&ctx->sync_expunges);
		}
		seq_range_array_merge(&bbox->sync_pending_removes,
				      &removed_uids);
	} else if (array_count(&bbox->sync_pending_removes) > 0) {
		/* remove all current and old */
		seq_range_array_merge(&bbox->sync_pending_removes,
				      &removed_uids);
		virtual_sync_mailbox_box_remove(ctx, bbox,
						&bbox->sync_pending_removes);
		array_clear(&bbox->sync_pending_removes);
	} else {
		virtual_sync_mailbox_box_remove(ctx, bbox, &removed_uids);
	}
	virtual_sync_mailbox_box_add(ctx, bbox, &added_uids);
}

static bool virtual_sync_find_seqs(struct virtual_backend_box *bbox,
				   const struct mailbox_sync_rec *sync_rec,
				   unsigned int *idx1_r,
				   unsigned int *idx2_r)
{
	const struct virtual_backend_uidmap *uidmap;
	unsigned int idx, count;
	uint32_t uid1, uid2;

	mail_index_lookup_uid(bbox->box->view, sync_rec->seq1, &uid1);
	mail_index_lookup_uid(bbox->box->view, sync_rec->seq2, &uid2);
	(void)array_bsearch_insert_pos(&bbox->uids, &uid1,
				       virtual_backend_uidmap_bsearch_cmp,
				       &idx);

	uidmap = array_get_modifiable(&bbox->uids, &count);
	if (idx == count || uidmap[idx].real_uid > uid2)
		return FALSE;

	*idx1_r = idx;
	while (idx < count && uidmap[idx].real_uid <= uid2) idx++;
	*idx2_r = idx - 1;
	return TRUE;
}

static void virtual_sync_expunge_add(struct virtual_sync_context *ctx,
				     struct virtual_backend_box *bbox,
				     const struct mailbox_sync_rec *sync_rec)
{
	struct virtual_backend_uidmap *uidmap;
	uint32_t uid1, uid2;
	unsigned int i, idx1, count;

	mail_index_lookup_uid(bbox->box->view, sync_rec->seq1, &uid1);
	mail_index_lookup_uid(bbox->box->view, sync_rec->seq2, &uid2);

	/* remember only the expunges for messages that
	   already exist for this mailbox */
	(void)array_bsearch_insert_pos(&bbox->uids, &uid1,
				       virtual_backend_uidmap_bsearch_cmp,
				       &idx1);
	uidmap = array_get_modifiable(&bbox->uids, &count);
	for (i = idx1; i < count; i++) {
		if (uidmap[i].real_uid > uid2)
			break;
		seq_range_array_add(&ctx->sync_expunges, 0, uidmap[i].real_uid);
	}
}

static int virtual_sync_backend_box_sync(struct virtual_sync_context *ctx,
					 struct virtual_backend_box *bbox,
					 enum mailbox_sync_flags sync_flags)
{
	struct mailbox_sync_context *sync_ctx;
	const struct virtual_backend_uidmap *uidmap;
	struct mailbox_sync_rec sync_rec;
	struct mailbox_sync_status sync_status;
	unsigned int idx1, idx2;
	uint32_t vseq, vuid;

	sync_ctx = mailbox_sync_init(bbox->box, sync_flags);
	virtual_backend_box_sync_mail_set(bbox);
	while (mailbox_sync_next(sync_ctx, &sync_rec)) {
		switch (sync_rec.type) {
		case MAILBOX_SYNC_TYPE_EXPUNGE:
			if (ctx->expunge_removed) {
				/* no need to keep track of expunges */
				break;
			}
			virtual_sync_expunge_add(ctx, bbox, &sync_rec);
			break;
		case MAILBOX_SYNC_TYPE_FLAGS:
			if (!virtual_sync_find_seqs(bbox, &sync_rec,
						    &idx1, &idx2))
				break;
			uidmap = array_idx(&bbox->uids, 0);
			for (; idx1 <= idx2; idx1++) {
				vuid = uidmap[idx1].virtual_uid;
				if (!mail_index_lookup_seq(ctx->sync_view,
							   vuid, &vseq)) {
					/* expunged by another session,
					   but we haven't yet updated
					   bbox->uids. */
					continue;
				}
				virtual_sync_external_flags(ctx, bbox, vseq,
							uidmap[idx1].real_uid);
			}
			break;
		case MAILBOX_SYNC_TYPE_MODSEQ:
			break;
		}
	}
	return mailbox_sync_deinit(&sync_ctx, &sync_status);
}

static void virtual_sync_backend_ext_header(struct virtual_sync_context *ctx,
					    struct virtual_backend_box *bbox)
{
	const unsigned int uidval_pos =
		offsetof(struct virtual_mail_index_mailbox_record,
			 uid_validity);
	struct mailbox_status status;
	struct virtual_mail_index_mailbox_record mailbox;
	unsigned int mailbox_offset;
	uint64_t wanted_ondisk_highest_modseq;

	mailbox_get_status(bbox->box, STATUS_UIDVALIDITY |
			   STATUS_HIGHESTMODSEQ, &status);
	wanted_ondisk_highest_modseq =
		array_count(&bbox->sync_pending_removes) > 0 ? 0 :
		status.highest_modseq;

	if (bbox->sync_uid_validity == status.uidvalidity &&
	    bbox->sync_next_uid == status.uidnext &&
	    bbox->sync_highest_modseq == status.highest_modseq &&
	    bbox->ondisk_highest_modseq == wanted_ondisk_highest_modseq)
		return;

	/* mailbox changed - update extension header */
	bbox->sync_uid_validity = status.uidvalidity;
	bbox->sync_highest_modseq = status.highest_modseq;
	bbox->ondisk_highest_modseq = wanted_ondisk_highest_modseq;
	bbox->sync_next_uid = status.uidnext;

	if (ctx->ext_header_rewrite) {
		/* we'll rewrite the entire header later */
		return;
	}

	memset(&mailbox, 0, sizeof(mailbox));
	mailbox.uid_validity = bbox->sync_uid_validity;
	mailbox.highest_modseq = bbox->ondisk_highest_modseq;
	mailbox.next_uid = bbox->sync_next_uid;

	mailbox_offset = sizeof(struct virtual_mail_index_header) +
		bbox->sync_mailbox_idx * sizeof(mailbox);
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext_id,
				     mailbox_offset + uidval_pos,
				     CONST_PTR_OFFSET(&mailbox, uidval_pos),
				     sizeof(mailbox) - uidval_pos);
	ctx->ext_header_changed = TRUE;
}

static int virtual_sync_backend_box(struct virtual_sync_context *ctx,
				    struct virtual_backend_box *bbox)
{
	enum mailbox_sync_flags sync_flags;
	struct mailbox_status status;
	int ret;

	if (!bbox->box->opened) {
		if (mailbox_open(bbox->box) < 0)
			return -1;
	}

	/* if we already did some changes to index, commit them before
	   syncing starts. */
	virtual_backend_box_sync_mail_unset(bbox);
	/* we use modseqs for speeding up initial search result build.
	   make sure the backend has them enabled. */
	mail_index_modseq_enable(bbox->box->index);

	sync_flags = ctx->flags & (MAILBOX_SYNC_FLAG_FULL_READ |
				   MAILBOX_SYNC_FLAG_FULL_WRITE |
				   MAILBOX_SYNC_FLAG_FAST);

	if (bbox->search_result == NULL) {
		/* first sync in this process */
		i_assert(ctx->expunge_removed);

		if (mailbox_sync(bbox->box, sync_flags) < 0)
			return -1;

		mailbox_get_status(bbox->box, STATUS_UIDVALIDITY, &status);
		virtual_backend_box_sync_mail_set(bbox);
		if (status.uidvalidity != bbox->sync_uid_validity) {
			/* UID validity changed since last sync (or this is
			   the first sync), do a full search */
			ret = virtual_sync_backend_box_init(bbox);
		} else {
			/* build the initial search using the saved modseq. */
			ret = virtual_sync_backend_box_continue(ctx, bbox);
		}
	} else {
		/* sync using the existing search result */
		i_array_init(&ctx->sync_expunges, 32);
		ret = virtual_sync_backend_box_sync(ctx, bbox, sync_flags);
		if (ret == 0) T_BEGIN {
			virtual_sync_mailbox_box_update(ctx, bbox);
		} T_END;
		array_free(&ctx->sync_expunges);
	}

	virtual_sync_backend_ext_header(ctx, bbox);
	return ret;
}

static void virtual_sync_backend_map_uids(struct virtual_sync_context *ctx)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_sync_mail *vmails;
	struct virtual_backend_box *bbox;
	struct virtual_backend_uidmap *uidmap = NULL;
	struct virtual_add_record add_rec;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	bool expunged;
	uint32_t i, vseq, vuid, messages;
	unsigned int j = 0, uidmap_count = 0;

	messages = mail_index_view_get_messages_count(ctx->sync_view);
	if (messages == 0)
		return;

	/* sort the messages in current view by their backend mailbox and
	   real UID */
	vmails = i_new(struct virtual_sync_mail, messages);
	for (vseq = 1; vseq <= messages; vseq++) {
		mail_index_lookup_ext(ctx->sync_view, vseq, virtual_ext_id,
				      &data, &expunged);
		vrec = data;
		vmails[vseq-1].vseq = vseq;
		vmails[vseq-1].vrec = *vrec;
	}
	qsort(vmails, messages, sizeof(*vmails), virtual_sync_mail_cmp);

	/* create real mailbox uid -> virtual uid mapping and expunge
	   messages no longer matching the search rule */
	memset(&add_rec, 0, sizeof(add_rec));
	bbox = NULL;
	for (i = 0; i < messages; i++) {
		vseq = vmails[i].vseq;
		vrec = &vmails[i].vrec;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			/* add the rest of the newly seen messages */
			for (; j < uidmap_count; j++) {
				add_rec.rec.real_uid = uidmap[j].real_uid;
				array_append(&ctx->all_adds, &add_rec, 1);
			}
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
			if (bbox == NULL) {
				/* the entire mailbox is lost */
				mail_index_expunge(ctx->trans, vseq);
				continue;
			}
			uidmap = array_get_modifiable(&bbox->uids,
						      &uidmap_count);
			j = 0;
			add_rec.rec.mailbox_id = bbox->mailbox_id;
			bbox->sync_seen = TRUE;
		}
		mail_index_lookup_uid(ctx->sync_view, vseq, &vuid);

		/* if virtual record doesn't exist in uidmap, it's expunged */
		for (; j < uidmap_count; j++) {
			if (uidmap[j].real_uid >= vrec->real_uid)
				break;

			/* newly seen message */
			add_rec.rec.real_uid = uidmap[j].real_uid;
			array_append(&ctx->all_adds, &add_rec, 1);
		}
		if (j == uidmap_count || uidmap[j].real_uid != vrec->real_uid)
			mail_index_expunge(ctx->trans, vseq);
		else {
			/* exists - update uidmap and flags */
			uidmap[j++].virtual_uid = vuid;
			virtual_sync_external_flags(ctx, bbox, vseq,
						    vrec->real_uid);
		}
	}
	i_free(vmails);

	/* finish adding messages to the last mailbox */
	for (; j < uidmap_count; j++) {
		add_rec.rec.real_uid = uidmap[j].real_uid;
		array_append(&ctx->all_adds, &add_rec, 1);
	}
}

static void virtual_sync_new_backend_boxes(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	struct virtual_add_record add_rec;
	struct virtual_backend_uidmap *uidmap;
	unsigned int i, j, count, uidmap_count;

	/* if there are any mailboxes we didn't yet sync, add new messages in
	   them */
	memset(&add_rec, 0, sizeof(add_rec));
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->sync_seen)
			continue;

		add_rec.rec.mailbox_id = bboxes[i]->mailbox_id;
		uidmap = array_get_modifiable(&bboxes[i]->uids, &uidmap_count);
		for (j = 0; j < uidmap_count; j++) {
			add_rec.rec.real_uid = uidmap[j].real_uid;
			array_append(&ctx->all_adds, &add_rec, 1);
		}
	}
}

static int virtual_add_record_cmp(const struct virtual_add_record *add1,
				  const struct virtual_add_record *add2)
{
	if (add1->received_date < add2->received_date)
		return -1;
	if (add1->received_date > add2->received_date)
		return 1;

	/* if they're in same mailbox, we can order them correctly by the UID.
	   if they're in different mailboxes, ordering by UID doesn't really
	   help but it doesn't really harm either. */
	if (add1->rec.real_uid < add2->rec.real_uid)
		return -1;
	if (add1->rec.real_uid > add2->rec.real_uid)
		return 1;

	/* two messages in different mailboxes have the same received date
	   and UID. */
	return 0;
}

static void virtual_sync_backend_sort_new(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *bbox;
	struct virtual_add_record *adds;
	const struct virtual_mail_index_record *vrec;
	unsigned int i, count;

	/* get all messages' received dates */
	adds = array_get_modifiable(&ctx->all_adds, &count);
	for (bbox = NULL, i = 0; i < count; i++) {
		vrec = &adds[i].rec;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
		}
		if (!mail_set_uid(bbox->sync_mail, vrec->real_uid))
			i_unreached();
		if (mail_get_received_date(bbox->sync_mail,
					   &adds[i].received_date) < 0) {
			/* probably expunged already, just add it somewhere */
			adds[i].received_date = 0;
		}
	}

	array_sort(&ctx->all_adds, virtual_add_record_cmp);
}

static void virtual_sync_backend_add_new(struct virtual_sync_context *ctx)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_add_record *adds;
	struct virtual_backend_box *bbox;
	struct virtual_backend_uidmap *uidmap;
	const struct mail_index_header *hdr;
	const struct virtual_mail_index_record *vrec;
	unsigned int i, count, idx;
	ARRAY_TYPE(seq_range) saved_uids;
	uint32_t vseq, first_uid;

	hdr = mail_index_get_header(ctx->sync_view);
	adds = array_get_modifiable(&ctx->all_adds, &count);
	if (count == 0) {
		ctx->mbox->sync_virtual_next_uid = hdr->next_uid;
		return;
	}

	if (adds[0].rec.mailbox_id == adds[count-1].rec.mailbox_id) {
		/* all messages are from a single mailbox. add them in
		   the same order. */
	} else {
		/* sort new messages by received date to get the add order */
		virtual_sync_backend_sort_new(ctx);
	}

	for (bbox = NULL, i = 0; i < count; i++) {
		vrec = &adds[i].rec;
		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
		}

		mail_index_append(ctx->trans, 0, &vseq);
		mail_index_update_ext(ctx->trans, vseq, virtual_ext_id,
				      vrec, NULL);
		virtual_sync_external_flags(ctx, bbox, vseq, vrec->real_uid);
	}

	/* assign UIDs to new messages */
	first_uid = hdr->next_uid;
	t_array_init(&saved_uids, 1);
	mail_index_append_finish_uids(ctx->trans, first_uid, &saved_uids);
	i_assert(seq_range_count(&saved_uids) == count);

	/* update virtual UIDs in uidmap */
	for (bbox = NULL, i = 0; i < count; i++) {
		vrec = &adds[i].rec;
		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
		}

		if (!array_bsearch_insert_pos(&bbox->uids, &vrec->real_uid,
					      virtual_backend_uidmap_bsearch_cmp,
					      &idx))
			i_unreached();
		uidmap = array_idx_modifiable(&bbox->uids, idx);
		i_assert(uidmap->virtual_uid == 0);
		uidmap->virtual_uid = first_uid + i;
	}
	ctx->mbox->sync_virtual_next_uid = first_uid + i;
}

static int
virtual_sync_apply_existing_appends(struct virtual_sync_context *ctx)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_backend_box *bbox = NULL;
	const struct mail_index_header *hdr;
	const struct virtual_mail_index_record *vrec;
	struct virtual_backend_uidmap uidmap;
	const void *data;
	bool expunged;
	uint32_t seq, seq2;

	if (!ctx->mbox->uids_mapped)
		return 0;

	hdr = mail_index_get_header(ctx->sync_view);
	if (ctx->mbox->sync_virtual_next_uid >= hdr->next_uid)
		return 0;

	/* another process added messages to virtual index. get backend boxes'
	   uid lists up-to-date by adding the new messages there. */
	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 ctx->mbox->sync_virtual_next_uid,
					 (uint32_t)-1, &seq, &seq2))
		return 0;

	memset(&uidmap, 0, sizeof(uidmap));
	for (; seq <= seq2; seq++) {
		mail_index_lookup_ext(ctx->sync_view, seq, virtual_ext_id,
				      &data, &expunged);
		vrec = data;
		uidmap.real_uid = vrec->real_uid;
		mail_index_lookup_uid(ctx->sync_view, seq, &uidmap.virtual_uid);

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
			if (bbox == NULL) {
				mail_storage_set_critical(
					ctx->mbox->box.storage,
					"Mailbox ID %u unexpectedly lost",
					vrec->mailbox_id);
				return -1;
			}
		}
		array_append(&bbox->uids, &uidmap, 1);
		bbox->uids_nonsorted = TRUE;
	}

	virtual_sync_backend_boxes_sort_uids(ctx->mbox);
	return 0;
}

static void
virtual_sync_apply_existing_expunges(struct virtual_mailbox *mbox,
				     struct mailbox_sync_context *sync_ctx)
{
	struct index_mailbox_sync_context *isync_ctx =
		(struct index_mailbox_sync_context *)sync_ctx;
	struct virtual_backend_box *bbox = NULL;
	struct seq_range_iter iter;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	bool expunged;
	unsigned int n = 0;
	uint32_t seq;

	if (isync_ctx->expunges == NULL)
		return;

	seq_range_array_iter_init(&iter, isync_ctx->expunges);
	while (seq_range_array_iter_nth(&iter, n++, &seq)) {
		mail_index_lookup_ext(mbox->box.view, seq,
				      mbox->virtual_ext_id, &data, &expunged);
		vrec = data;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(mbox,
							  vrec->mailbox_id);
			if (!array_is_created(&bbox->sync_outside_expunges))
				i_array_init(&bbox->sync_outside_expunges, 32);
		}
		seq_range_array_add(&bbox->sync_outside_expunges, 0,
				    vrec->real_uid);
	}
}

static int virtual_sync_backend_boxes(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	if (virtual_sync_apply_existing_appends(ctx) < 0)
		return -1;

	i_array_init(&ctx->all_adds, 128);
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (virtual_sync_backend_box(ctx, bboxes[i]) < 0) {
			/* backend failed, copy the error */
			virtual_box_copy_error(&ctx->mbox->box,
					       bboxes[i]->box);
			return -1;
		}
	}

	if (!ctx->mbox->uids_mapped) {
		/* initial sync: assign virtual UIDs to existing messages and
		   sync all flags */
		ctx->mbox->uids_mapped = TRUE;
		virtual_sync_backend_map_uids(ctx);
		virtual_sync_new_backend_boxes(ctx);
	}
	virtual_sync_backend_add_new(ctx);
	array_free(&ctx->all_adds);
	return 0;
}

static void virtual_sync_backend_boxes_finish(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++)
		virtual_backend_box_sync_mail_unset(bboxes[i]);
}

static int virtual_sync_finish(struct virtual_sync_context *ctx, bool success)
{
	int ret = success ? 0 : -1;

	virtual_sync_backend_boxes_finish(ctx);
	if (success) {
		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mail_storage_set_index_error(&ctx->mbox->box);
			ret = -1;
		}
	} else {
		if (ctx->index_broken) {
			/* make sure we don't complain about the same errors
			   over and over again. */
			if (mail_index_unlink(ctx->index) < 0) {
				i_error("virtual index %s: Failed to unlink() "
					"broken indexes: %m",
					ctx->mbox->box.path);
			}
		}
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}
	i_free(ctx);
	return ret;
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
	ctx->index = mbox->box.index;
	/* Removed messages are expunged when
	   a) EXPUNGE is used
	   b) Mailbox is being opened (FIX_INCONSISTENT is set) */
	ctx->expunge_removed =
		(ctx->flags & (MAILBOX_SYNC_FLAG_EXPUNGE |
			       MAILBOX_SYNC_FLAG_FIX_INCONSISTENT)) != 0;

	index_sync_flags = MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY |
		MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;
	if ((mbox->box.flags & MAILBOX_FLAG_KEEP_RECENT) == 0)
		index_sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;

	ret = mail_index_sync_begin(ctx->index, &ctx->index_sync_ctx,
				    &ctx->sync_view, &ctx->trans,
				    index_sync_flags);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->box);
		i_free(ctx);
		return ret;
	}

	ret = virtual_sync_ext_header_read(ctx);
	if (ret < 0)
		return virtual_sync_finish(ctx, FALSE);
	if (ret == 0)
		ctx->ext_header_rewrite = TRUE;
	/* apply changes from virtual index to backend mailboxes */
	virtual_sync_index_changes(ctx);
	/* update list of UIDs in backend mailboxes */
	if (virtual_sync_backend_boxes(ctx) < 0)
		return virtual_sync_finish(ctx, FALSE);

	virtual_sync_index_finish(ctx);
	return virtual_sync_finish(ctx, TRUE);
}

struct mailbox_sync_context *
virtual_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct mailbox_sync_context *sync_ctx;
	int ret = 0;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			ret = -1;
	}

	if (index_mailbox_want_full_sync(&mbox->box, flags) && ret == 0)
		ret = virtual_sync(mbox, flags);

	sync_ctx = index_mailbox_sync_init(box, flags, ret < 0);
	virtual_sync_apply_existing_expunges(mbox, sync_ctx);
	return sync_ctx;
}
