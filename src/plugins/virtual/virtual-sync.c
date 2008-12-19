/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "ioloop.h"
#include "str.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-search-result-private.h"
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
	unsigned int retry:1;
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
	keywords = mail_index_keywords_create(ctx->index, kw_names);
	mail_index_update_keywords(ctx->trans, vseq, MODIFY_REPLACE, keywords);
	mail_index_keywords_free(&keywords);
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

static int bbox_mailbox_id_cmp(const void *p1, const void *p2)
{
	const struct virtual_backend_box *const *b1 = p1, *const *b2 = p2;

	if ((*b1)->mailbox_id < (*b2)->mailbox_id)
		return -1;
	if ((*b1)->mailbox_id > (*b2)->mailbox_id)
		return 1;
	return 0;
}

static bool virtual_sync_ext_header_read(struct virtual_sync_context *ctx)
{
	const struct virtual_mail_index_header *ext_hdr;
	const struct mail_index_header *hdr;
	const struct virtual_mail_index_mailbox_record *mailboxes;
	struct virtual_backend_box *bbox, **bboxes;
	const void *ext_data;
	size_t ext_size;
	unsigned int i, count, ext_name_offset, ext_mailbox_count;
	uint32_t prev_mailbox_id;
	bool ret;

	hdr = mail_index_get_header(ctx->sync_view);
	mail_index_get_header_ext(ctx->sync_view, ctx->mbox->virtual_ext_id,
				  &ext_data, &ext_size);
	ext_hdr = ext_data;
	if (ctx->mbox->sync_initialized &&
	    ctx->mbox->prev_uid_validity == hdr->uid_validity &&
	    ext_size >= sizeof(*ext_hdr) &&
	    ctx->mbox->prev_change_counter == ext_hdr->change_counter) {
		/* fully refreshed */
		return TRUE;
	}

	ctx->mbox->sync_initialized = TRUE;
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
			i_error("virtual %s: Broken mailbox_count header",
				ctx->mbox->path);
			ext_mailbox_count = 0;
		} else {
			ext_mailbox_count = ext_hdr->mailbox_count;
		}
	}

	/* update mailbox backends */
	prev_mailbox_id = 0;
	for (i = 0; i < ext_mailbox_count; i++) {
		if (mailboxes[i].id > ext_hdr->highest_mailbox_id ||
		    mailboxes[i].id <= prev_mailbox_id) {
			i_error("virtual %s: Broken mailbox id",
				ctx->mbox->path);
			break;
		}
		if (mailboxes[i].name_len == 0 ||
		    mailboxes[i].name_len > ext_size) {
			i_error("virtual %s: Broken mailbox name_len",
				ctx->mbox->path);
			break;
		}
		if (ext_name_offset + mailboxes[i].name_len > ext_size) {
			i_error("virtual %s: Broken mailbox list",
				ctx->mbox->path);
			break;
		}
		T_BEGIN {
			const unsigned char *nameptr;
			const char *name;

			nameptr = CONST_PTR_OFFSET(ext_data, ext_name_offset);
			name = t_strndup(nameptr, mailboxes[i].name_len);
			bbox = virtual_backend_box_lookup_name(ctx->mbox, name);
		} T_END;
		if (bbox == NULL) {
			/* mailbox no longer exists */
			ret = FALSE;
		} else {
			bbox->mailbox_id = mailboxes[i].id;
			bbox->sync_uid_validity = mailboxes[i].uid_validity;
			bbox->sync_highest_modseq = mailboxes[i].highest_modseq;
			bbox->sync_next_uid = mailboxes[i].next_uid;
			bbox->sync_mailbox_idx = i;
		}
		ext_name_offset += mailboxes[i].name_len;
		prev_mailbox_id = mailboxes[i].id;
	}
	if (ext_hdr == NULL) {
		ret = TRUE;
		ctx->mbox->highest_mailbox_id = 0;
	} else {
		ret = i == ext_hdr->mailbox_count;
		ctx->mbox->highest_mailbox_id = ext_hdr->highest_mailbox_id;
	}

	/* assign new mailbox IDs if any are missing */
	bboxes = array_get_modifiable(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->mailbox_id == 0) {
			bboxes[i]->mailbox_id = ++ctx->mbox->highest_mailbox_id;
			ret = FALSE;
		}
	}
	/* sort the backend mailboxes by mailbox_id. */
	qsort(bboxes, count, sizeof(*bboxes), bbox_mailbox_id_cmp);
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
		mailbox.highest_modseq = bboxes[i]->sync_highest_modseq;
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
	struct mailbox *box = &ctx->mbox->ibox.box;
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
		index_mailbox_set_recent_seq(&ctx->mbox->ibox, ctx->sync_view,
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

	mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);
	search_ctx = mailbox_search_init(trans, bbox->search_args, NULL);

	/* save the result and keep it updated */
	result_flags = MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
		MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC;
	bbox->search_result =
		mailbox_search_result_save(search_ctx, result_flags);

	/* add the found UIDs to uidmap. virtual_uid gets assigned later. */
	memset(&uidmap, 0, sizeof(uidmap));
	array_clear(&bbox->uids);
	while (mailbox_search_next(search_ctx, mail) > 0) {
		uidmap.real_uid = mail->uid;
		array_append(&bbox->uids, &uidmap, 1);
	}

	ret = mailbox_search_deinit(&search_ctx);
	mail_free(&mail);

	mail_search_args_deinit(bbox->search_args);
	(void)mailbox_transaction_commit(&trans);
	return ret;
}

static int virtual_backend_uidmap_cmp(const void *p1, const void *p2)
{
	const struct virtual_backend_uidmap *u1 = p1, *u2 = p2;

	if (u1->real_uid < u2->real_uid)
		return -1;
	if (u1->real_uid > u2->real_uid)
		return 1;
	return 0;
}

static void
virtual_sync_backend_add_existing_uids(struct virtual_sync_context *ctx,
				       struct virtual_backend_box *bbox,
				       struct mail_search_result *result)
{
	struct virtual_backend_uidmap uidmap, *uids;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	uint32_t vseq, vuid, messages;
	unsigned int uid_count;
	bool expunged;

	/* add the currently existing UIDs to uidmap. */
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
			seq_range_array_add(&result->uids, 0, vrec->real_uid);
			uidmap.real_uid = vrec->real_uid;
			uidmap.virtual_uid = vuid;
			array_append(&bbox->uids, &uidmap, 1);
		}
	}

	/* the uidmap must be sorted by real_uids */
	uids = array_get_modifiable(&bbox->uids, &uid_count);
	qsort(uids, uid_count, sizeof(*uids), virtual_backend_uidmap_cmp);
}

static void
virtual_sync_backend_remove_expunged_uids(struct mail_search_result *result)
{
	struct index_mailbox *ibox = (struct index_mailbox *)result->box;
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq, uid;

	range = array_get(&result->uids, &count);
	for (i = 0; i < count; i++) {
		for (uid = range[i].seq1; uid <= range[i].seq2; uid++) {
			if (!mail_index_lookup_seq(ibox->view, uid, &seq))
				mailbox_search_result_remove(result, uid);
		}
	}
}

static int virtual_sync_backend_box_continue(struct virtual_sync_context *ctx,
					     struct virtual_backend_box *bbox)
{
	const enum mailbox_search_result_flags result_flags =
		MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
		MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC;
	struct index_mailbox *ibox = (struct index_mailbox *)bbox->box;
	struct mail_search_result *result;
	ARRAY_TYPE(seq_range) flag_updates;
	uint64_t modseq;
	uint32_t seq, old_msg_count;

	/* build the initial search result from the existing UIDs */
	result = mailbox_search_result_alloc(bbox->box, bbox->search_args,
					     result_flags);
	mailbox_search_result_initial_done(result);
	virtual_sync_backend_add_existing_uids(ctx, bbox, result);

	/* changes done from now on must update the sync queue */
	virtual_sync_backend_remove_expunged_uids(result);

	/* get list of changed messages */
	if (bbox->sync_next_uid <= 1 ||
	    !mail_index_lookup_seq_range(ibox->view, 1, bbox->sync_next_uid-1,
					 &seq, &old_msg_count))
		old_msg_count = 0;
	t_array_init(&flag_updates, I_MIN(128, old_msg_count));
	for (seq = 1; seq <= old_msg_count; seq++) {
		modseq = mail_index_modseq_lookup(ibox->view, seq);
		if (modseq > bbox->sync_highest_modseq)
			seq_range_array_add(&flag_updates, 0, seq);
	}

	if (index_search_result_update_flags(result, &flag_updates) < 0 ||
	    index_search_result_update_appends(result, old_msg_count) < 0) {
		mailbox_search_result_free(&result);
		return -1;
	}

	bbox->search_result = result;
	return 0;
}

static int virtual_backend_uidmap_bsearch_cmp(const void *key, const void *data)
{
	const uint32_t *uidp = key;
	const struct virtual_backend_uidmap *uidmap = data;

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
	unsigned int i, src, dest, uid_count, rec_count, left;
	uint32_t uid, vseq;

	uids = array_get(removed_uids, &uid_count);
	if (uid_count == 0)
		return;

	/* everything in removed_uids should exist in bbox->uids */
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	i_assert(rec_count >= uid_count);

	/* find the first uidmap record to be removed */
	if (!bsearch_insert_pos(&uids[0].seq1, uidmap, rec_count,
				sizeof(*uidmap),
				virtual_backend_uidmap_bsearch_cmp, &src))
		i_unreached();

	/* remove the unwanted messages */
	for (i = src = dest = 0; i < uid_count; i++) {
		uid = uids[i].seq1;
		while (uidmap[src].real_uid != uid) {
			uidmap[dest++] = uidmap[src++];
			i_assert(src < rec_count);
		}

		for (; uid <= uids[i].seq2; uid++, src++) {
			if (!mail_index_lookup_seq(ctx->sync_view,
						   uidmap[src].virtual_uid,
						   &vseq))
				i_unreached();
			mail_index_expunge(ctx->trans, vseq);
		}
	}
	left = rec_count - src;
	memmove(uidmap + dest, uidmap + src, left);
	array_delete(&bbox->uids, dest + left, src - dest);
}

static void
virtual_sync_mailbox_box_add(struct virtual_sync_context *ctx,
			     struct virtual_backend_box *bbox,
			     const ARRAY_TYPE(seq_range) *added_uids)
{
	const struct seq_range *uids;
	struct virtual_backend_uidmap *uidmap;
	struct virtual_add_record rec;
	unsigned int i, src, dest, uid_count, add_count, rec_count;
	uint32_t uid;

	uids = array_get(added_uids, &uid_count);
	if (uid_count == 0)
		return;
	add_count = seq_range_count(added_uids);

	/* none of added_uids should exist in bbox->uids. find the position
	   of the first inserted index. */
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	if (rec_count == 0 || uids[0].seq1 > uidmap[rec_count-1].real_uid) {
		/* fast path: usually messages are appended */
		dest = rec_count;
	} else if (bsearch_insert_pos(&uids[0].seq1, uidmap, rec_count,
				      sizeof(*uidmap),
				      virtual_backend_uidmap_bsearch_cmp,
				      &dest))
		i_unreached();

	/* make space for all added UIDs. */
	array_copy(&bbox->uids.arr, dest + add_count,
		   &bbox->uids.arr, dest, rec_count - dest);
	uidmap = array_get_modifiable(&bbox->uids, &rec_count);
	src = dest + add_count;

	/* add/move the UIDs to their correct positions */
	memset(&rec, 0, sizeof(rec));
	rec.rec.mailbox_id = bbox->mailbox_id;
	for (i = 0; i < uid_count; i++) {
		uid = uids[i].seq1;
		while (src < rec_count && uidmap[src].real_uid < uid) {
			uidmap[dest++] = uidmap[src++];
			i_assert(src < rec_count);
		}

		for (; uid <= uids[i].seq2; uid++, dest++) {
			uidmap[dest].real_uid = uid;
			uidmap[dest].virtual_uid = 0;

			rec.rec.real_uid = uid;
			array_append(&ctx->all_adds, &rec, 1);
		}
	}
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
	struct index_mailbox *ibox = (struct index_mailbox *)bbox->box;
	const struct virtual_backend_uidmap *uidmap;
	unsigned int idx, count;
	uint32_t uid1, uid2;

	mail_index_lookup_uid(ibox->view, sync_rec->seq1, &uid1);
	mail_index_lookup_uid(ibox->view, sync_rec->seq2, &uid2);
	uidmap = array_get_modifiable(&bbox->uids, &count);
	(void)bsearch_insert_pos(&uid1, uidmap, count, sizeof(*uidmap),
				 virtual_backend_uidmap_bsearch_cmp, &idx);
	if (idx == count || uidmap[idx].real_uid > uid2)
		return FALSE;

	*idx1_r = idx;
	while (idx < count && uidmap[idx].real_uid <= uid2) idx++;
	*idx2_r = idx - 1;
	return TRUE;
}

static int virtual_sync_backend_box_sync(struct virtual_sync_context *ctx,
					 struct virtual_backend_box *bbox,
					 enum mailbox_sync_flags sync_flags)
{
	struct mailbox_sync_context *sync_ctx;
	const struct virtual_backend_uidmap *uidmap;
	struct mailbox_sync_rec sync_rec;
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
			seq_range_array_add_range(&ctx->sync_expunges,
						  sync_rec.seq1, sync_rec.seq2);
			break;
		case MAILBOX_SYNC_TYPE_FLAGS:
			if (!virtual_sync_find_seqs(bbox, &sync_rec,
						    &idx1, &idx2))
				break;
			uidmap = array_idx(&bbox->uids, 0);
			for (; idx1 <= idx2; idx1++) {
				vuid = uidmap[idx1].virtual_uid;
				if (!mail_index_lookup_seq(ctx->sync_view,
							   vuid, &vseq))
					i_unreached();
				virtual_sync_external_flags(ctx, bbox, vseq,
							uidmap[idx1].real_uid);
			}
			break;
		case MAILBOX_SYNC_TYPE_MODSEQ:
			break;
		}
	}
	return mailbox_sync_deinit(&sync_ctx, 0, NULL);
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

	mailbox_get_status(bbox->box, STATUS_UIDVALIDITY |
			   STATUS_HIGHESTMODSEQ, &status);
	if (bbox->sync_uid_validity == status.uidvalidity &&
	    bbox->sync_next_uid == status.uidnext &&
	    bbox->sync_highest_modseq == status.highest_modseq)
		return;

	/* mailbox changed - update extension header */
	bbox->sync_uid_validity = status.uidvalidity;
	bbox->sync_highest_modseq = status.highest_modseq;
	bbox->sync_next_uid = status.uidnext;

	if (ctx->ext_header_rewrite) {
		/* we'll rewrite the entire header later */
		return;
	}

	memset(&mailbox, 0, sizeof(mailbox));
	mailbox.uid_validity = bbox->sync_uid_validity;
	mailbox.highest_modseq = bbox->sync_highest_modseq;
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
	struct index_mailbox *ibox = (struct index_mailbox *)bbox->box;
	enum mailbox_sync_flags sync_flags;
	struct mailbox_status status;
	int ret;

	if (!bbox->box->opened)
		index_storage_mailbox_open(ibox);

	/* if we already did some changes to index, commit them before
	   syncing starts. */
	virtual_backend_box_sync_mail_unset(bbox);
	/* we use modseqs for speeding up initial search result build.
	   make sure the backend has them enabled. */
	mail_index_modseq_enable(ibox->index);

	sync_flags = ctx->flags & (MAILBOX_SYNC_FLAG_FULL_READ |
				   MAILBOX_SYNC_FLAG_FULL_WRITE |
				   MAILBOX_SYNC_FLAG_FAST);

	if (bbox->search_result == NULL) {
		/* first sync in this process */
		i_assert(ctx->expunge_removed);

		if (mailbox_sync(bbox->box, sync_flags, STATUS_UIDVALIDITY,
				 &status) < 0)
			return -1;

		virtual_backend_box_sync_mail_set(bbox);
		if (status.uidvalidity != bbox->sync_uid_validity) {
			/* UID validity changed since last sync (or this is
			   the first sync), do a full search */
			ret = virtual_sync_backend_box_init(bbox);
		} else {
			/* build the initial search using the saved modseq.
			   we can't directly update the search result because
			   uidmap isn't finished for all messages yet, so
			   mark the sync to be retried. */
			ret = virtual_sync_backend_box_continue(ctx, bbox);
			ctx->retry = TRUE;
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
	struct virtual_backend_box *bbox, *const *bboxes;
	struct virtual_backend_uidmap *uidmap = NULL;
	struct virtual_add_record add_rec;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	bool expunged;
	uint32_t i, vseq, vuid, messages, count;
	unsigned int j = 0, uidmap_count = 0;

	messages = mail_index_view_get_messages_count(ctx->sync_view);

	/* sort the messages in current view by their backend mailbox and
	   real UID */
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
		if (uidmap[j].real_uid != vrec->real_uid)
			mail_index_expunge(ctx->trans, vseq);
		else {
			/* exists - update uidmap and flags */
			uidmap[j++].virtual_uid = vuid;
			/* if ctx->retry is set, we're just opening the virtual
			   mailbox and using a continued search using modseq.
			   some messages in uidmap may already be expunged, so
			   we can't go looking at the real messages yet.
			   after retrying the sync we'll get back here and
			   really do it. */
			if (!ctx->retry) {
				virtual_sync_external_flags(ctx, bbox, vseq,
							    vrec->real_uid);
			}
		}
	}
	i_free(vmails);

	/* finish adding messages to the last mailbox */
	for (; j < uidmap_count; j++) {
		add_rec.rec.real_uid = uidmap[j].real_uid;
		array_append(&ctx->all_adds, &add_rec, 1);
	}

	/* if there are any mailboxes we didn't yet sync, add new messages in
	   them */
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

static int virtual_add_record_cmp(const void *p1, const void *p2)
{
	const struct virtual_add_record *add1 = p1, *add2 = p2;

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

	qsort(adds, count, sizeof(*adds), virtual_add_record_cmp);
}

static void virtual_sync_backend_add_new(struct virtual_sync_context *ctx)
{
	uint32_t virtual_ext_id = ctx->mbox->virtual_ext_id;
	struct virtual_add_record *adds;
	struct virtual_backend_box *bbox;
	struct virtual_backend_uidmap *uidmap;
	const struct virtual_mail_index_record *vrec;
	unsigned int i, count, idx, uid_count;
	uint32_t vseq, first_uid, next_uid;

	adds = array_get_modifiable(&ctx->all_adds, &count);
	if (count == 0)
		return;

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
	first_uid = mail_index_get_header(ctx->sync_view)->next_uid;
	mail_index_append_assign_uids(ctx->trans, first_uid, &next_uid);

	/* update virtual UIDs in uidmap */
	for (bbox = NULL, i = 0; i < count; i++) {
		vrec = &adds[i].rec;
		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			bbox = virtual_backend_box_lookup(ctx->mbox,
							  vrec->mailbox_id);
		}

		uidmap = array_get_modifiable(&bbox->uids, &uid_count);
		if (!bsearch_insert_pos(&vrec->real_uid, uidmap, uid_count,
					sizeof(*uidmap),
					virtual_backend_uidmap_bsearch_cmp,
					&idx))
			i_unreached();
		i_assert(uidmap[idx].virtual_uid == 0);
		uidmap[idx].virtual_uid = first_uid + i;
	}
}

static int virtual_sync_backend_boxes(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	i_array_init(&ctx->all_adds, 128);
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (virtual_sync_backend_box(ctx, bboxes[i]) < 0) {
			/* backend failed, copy the error */
			virtual_box_copy_error(&ctx->mbox->ibox.box,
					       bboxes[i]->box);
			return -1;
		}
	}

	if (!ctx->mbox->uids_mapped) {
		/* initial sync: assign virtual UIDs to existing messages and
		   sync all flags */
		ctx->mbox->uids_mapped = TRUE;
		virtual_sync_backend_map_uids(ctx);
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
			mail_storage_set_index_error(&ctx->mbox->ibox);
			ret = -1;
		}
	} else {
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

	if (!virtual_sync_ext_header_read(ctx))
		ctx->ext_header_rewrite = TRUE;
	/* apply changes from virtual index to backend mailboxes */
	virtual_sync_index_changes(ctx);
	/* update list of UIDs in backend mailboxes */
	ret = virtual_sync_backend_boxes(ctx);
	if (ctx->retry && ret == 0) {
		ctx->retry = FALSE;
		/* map uids again to update changed message flags */
		ctx->mbox->uids_mapped = FALSE;
		ret = virtual_sync_backend_boxes(ctx);
		i_assert(!ctx->retry);
	}
	if (ret < 0)
		return virtual_sync_finish(ctx, FALSE);

	virtual_sync_index_finish(ctx);
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
