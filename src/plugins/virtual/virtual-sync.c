/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "ioloop.h"
#include "str.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-search-result-private.h"
#include "mailbox-recent-flags.h"
#include "index-sync-private.h"
#include "index-search-result.h"
#include "virtual-storage.h"

#define VIRTUAL_SYNC_LOCK_FNAME ".dovecot-virtual-sync.lock"
#define VIRTUAL_SYNC_LOCK_TIMEOUT_SECS (3*60)
#define VIRTUAL_SYNC_MAX_RETRIES 5

struct virtual_add_record {
	struct virtual_mail_index_record rec;
	time_t received_date;
};

struct virtual_sync_mail {
	uint32_t vseq;
	struct virtual_mail_index_record vrec;
};

/* A change that the virtual index has for a backend mailbox's mail */
struct virtual_backend_change {
	struct virtual_backend_box *bbox;
	uint32_t real_uid;
	/* order in which the changes were gathered */
	unsigned int idx;
	enum mail_index_sync_type type;
	enum mail_flags add_flags, remove_flags;
	/* keyword name for MAIL_INDEX_SYNC_TYPE_KEYWORD_{ADD,REMOVE} */
	const char *keyword;
};
ARRAY_DEFINE_TYPE(virtual_backend_change, struct virtual_backend_change);

struct virtual_sync_context {
	struct virtual_mailbox *mbox;
	struct mail_index *index;
	/* Private view of the virtual index. The sync is done against it
	   without locking the virtual index. */
	struct mail_index_view *view;
	/* External transaction for view, committed at the end of the sync
	   while the virtual index is locked. */
	struct mail_index_transaction *trans;
	enum mail_index_sync_flags index_sync_flags;

	/* messages expunged within this sync */
	ARRAY_TYPE(seq_range) sync_expunges;
	/* UIDs of the existing messages whose flags trans replaced */
	ARRAY_TYPE(seq_range) replaced_flag_uids;

	ARRAY(struct virtual_add_record) all_adds;

	/* all messages in this sync, sorted by mailbox_id
	   (but unsorted inside it for now, since it doesn't matter) */
	ARRAY(struct virtual_sync_mail) all_mails;
	uint32_t all_mails_idx, all_mails_prev_mailbox_id;

	enum mailbox_sync_flags flags;
	uint32_t uid_validity;

	/* The virtual index's transaction log position up to which its
	   changes have already been applied to the backend mailboxes. */
	uint32_t log_seq;
	uoff_t log_offset;

	bool ext_header_changed:1;
	bool expunge_removed:1;
	bool index_broken:1;
	/* fail instead of syncing again */
	bool last_try:1;
};

static void virtual_sync_backend_box_deleted(struct virtual_sync_context *ctx,
					     struct virtual_backend_box *bbox);

static void virtual_sync_set_uidvalidity(struct virtual_sync_context *ctx)
{
	uint32_t uid_validity = ioloop_time32;

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
		/* we may have reopened the mailbox, which could have
		   caused the mail to be expunged already. */
		return;
	}

	if (vseq <= mail_index_view_get_messages_count(ctx->view)) {
		uint32_t vuid;

		mail_index_lookup_uid(ctx->view, vseq, &vuid);
		if (!array_is_created(&ctx->replaced_flag_uids))
			i_array_init(&ctx->replaced_flag_uids, 32);
		seq_range_array_add(&ctx->replaced_flag_uids, vuid);
	}

	/* copy flags */
	flags = mail_get_flags(bbox->sync_mail);

	/* we don't need to keep recent flags here */
	mail_index_update_flags(ctx->trans, vseq, MODIFY_REPLACE,
				flags & ENUM_NEGATE(MAIL_RECENT));

	/* copy keywords */
	kw_names = mail_get_keywords(bbox->sync_mail);
	keywords = mail_index_keywords_create(ctx->index, kw_names);
	mail_index_update_keywords(ctx->trans, vseq, MODIFY_REPLACE, keywords);
	mail_index_keywords_unref(&keywords);
}

static int virtual_sync_mail_uid_cmp(const void *p1, const void *p2)
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
		trans = mailbox_transaction_begin(bbox->box, 0, __func__);
		bbox->sync_mail = mail_alloc(trans, 0, NULL);
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
virtual_sync_get_backend_box(struct virtual_mailbox *mbox, const char *name,
			     struct virtual_backend_box **bbox_r)
{
	*bbox_r = virtual_backend_box_lookup_name(mbox, name);
	if (*bbox_r != NULL || !mbox->sync_initialized)
		return 0;

	/* another process just added a new mailbox.
	   we can't handle this currently. */
	mbox->inconsistent = TRUE;
	mail_storage_set_error(mbox->box.storage, MAIL_ERROR_TEMP, t_strdup_printf(
		"Backend mailbox '%s' added by another session. "
		"Reopen the virtual mailbox.", name));
	return -1;
}

static bool
virtual_mailbox_ext2_header_read(struct virtual_mailbox *mbox,
				 struct mail_index_view *view,
				 const struct virtual_mail_index_header *ext_hdr)
{
	struct event *event = mbox->box.event;
	const char *box_path = mailbox_get_path(&mbox->box);
	const struct virtual_mail_index_ext2_header *ext2_hdr;
	const struct virtual_mail_index_mailbox_ext2_record *ext2_rec;
	const void *ext2_data;
	size_t ext2_size;
	struct virtual_backend_box *bbox;

	mail_index_get_header_ext(view, mbox->virtual_ext2_id,
				  &ext2_data, &ext2_size);
	ext2_hdr = ext2_data;
	if (ext2_size == 0) {
		/* ext2 is missing - silently add it */
		return FALSE;
	}
	if (ext2_size < sizeof(*ext2_hdr)) {
		e_error(event,
			"virtual index %s: Invalid ext2 header size: %zu",
			box_path, ext2_size);
		return FALSE;
	}
	if (ext2_hdr->hdr_size > ext2_size) {
		e_error(event,
			"virtual index %s: ext2 header size too large: %u > %zu",
			box_path, ext2_hdr->hdr_size, ext2_size);
		return FALSE;
	}
	if (ext2_hdr->ext_record_size < sizeof(*ext2_rec)) {
		e_error(event,
			"virtual index %s: Invalid ext2 record size: %u",
			box_path, ext2_hdr->ext_record_size);
		return FALSE;
	}

	if (ext_hdr->change_counter != ext2_hdr->change_counter) {
		e_warning(event,
			  "virtual index %s: "
			  "Extension header change_counter mismatch (%u != %u) - "
			  "Index was modified by an older version?",
			  box_path, ext_hdr->change_counter,
			  ext2_hdr->change_counter);
		return FALSE;
	}
	size_t mailboxes_size = ext2_size - ext2_hdr->hdr_size;
	if (mailboxes_size % ext2_hdr->ext_record_size != 0 ||
	    mailboxes_size / ext2_hdr->ext_record_size != ext_hdr->mailbox_count) {
		e_error(event,
			"virtual index %s: Invalid ext2 size: "
			"hdr_size=%u record_size=%u total_size=%zu mailbox_count=%u",
			box_path, ext2_hdr->hdr_size, ext2_hdr->ext_record_size,
			ext2_size, ext_hdr->mailbox_count);
		return FALSE;
	}

	ext2_rec = CONST_PTR_OFFSET(ext2_data, ext2_hdr->hdr_size);
	array_foreach_elem(&mbox->backend_boxes, bbox) {
		if (bbox->sync_mailbox_idx1 == 0)
			continue;

		guid_128_copy(bbox->sync_guid,
			      ext2_rec[bbox->sync_mailbox_idx1-1].guid);
	}
	return TRUE;
}

int virtual_mailbox_ext_header_read(struct virtual_mailbox *mbox,
				    struct mail_index_view *view,
				    bool *broken_r)
{
	struct event *event = mbox->box.event;
	const char *box_path = mailbox_get_path(&mbox->box);
	const struct virtual_mail_index_header *ext_hdr;
	const struct mail_index_header *hdr;
	const struct virtual_mail_index_mailbox_record *mailboxes;
	struct virtual_backend_box *bbox, **bboxes;
	const void *ext_data;
	size_t ext_size;
	unsigned int i, count, ext_name_offset, ext_mailbox_count;
	uint32_t prev_mailbox_id;
	int ret = 1;

	*broken_r = FALSE;

	hdr = mail_index_get_header(view);
	mail_index_get_header_ext(view, mbox->virtual_ext_id,
				  &ext_data, &ext_size);
	ext_hdr = ext_data;
	if (mbox->sync_initialized &&
	    mbox->prev_uid_validity == hdr->uid_validity &&
	    ext_size >= sizeof(*ext_hdr) &&
	    mbox->prev_change_counter == ext_hdr->change_counter) {
		/* fully refreshed */
		return 1;
	}

	mbox->prev_uid_validity = hdr->uid_validity;
	if (ext_hdr == NULL ||
	    mbox->search_args_crc32 != ext_hdr->search_args_crc32) {
		mailboxes = NULL;
		ext_name_offset = 0;
		ext_mailbox_count = 0;
		ret = 0;
	} else {
		const void *guid_data;
		size_t guid_size;
		mail_index_get_header_ext(view, mbox->virtual_guid_ext_id,
					  &guid_data, &guid_size);
		if (guid_size >= GUID_128_SIZE)
			guid_128_copy(mbox->guid, guid_data);

		mbox->prev_change_counter = ext_hdr->change_counter;
		mailboxes = (const void *)(ext_hdr + 1);
		ext_name_offset = sizeof(*ext_hdr) +
			ext_hdr->mailbox_count * sizeof(*mailboxes);
		if ((ext_name_offset == ext_size && ext_hdr->mailbox_count > 0) ||
		    ext_name_offset > ext_size ||
		    ext_hdr->mailbox_count > INT_MAX/sizeof(*mailboxes)) {
			e_error(event,
				"virtual index %s: Broken mailbox_count header",
				box_path);
			*broken_r = TRUE;
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
			e_error(event,
				"virtual index %s: Broken mailbox id",
				box_path);
			break;
		}
		if (mailboxes[i].name_len == 0 ||
		    mailboxes[i].name_len > ext_size) {
			e_error(event,
				"virtual index %s: Broken mailbox name_len",
				box_path);
			break;
		}
		if (ext_name_offset + mailboxes[i].name_len > ext_size) {
			e_error(event,
				"virtual index %s: Broken mailbox list",
				box_path);
			break;
		}
		T_BEGIN {
			const unsigned char *nameptr;
			const char *name;

			nameptr = CONST_PTR_OFFSET(ext_data, ext_name_offset);
			name = t_strndup(nameptr, mailboxes[i].name_len);
			if (virtual_sync_get_backend_box(mbox, name, &bbox) < 0)
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
			bbox->sync_mailbox_idx1 = i+1;
		}
		ext_name_offset += mailboxes[i].name_len;
		prev_mailbox_id = mailboxes[i].id;
	}
	if (i < ext_mailbox_count) {
		*broken_r = TRUE;
		mbox->ext_header_rewrite = TRUE;
		ret = 0;
	}
	if (!*broken_r && ext_mailbox_count > 0) {
		if (!virtual_mailbox_ext2_header_read(mbox, view, ext_hdr))
			mbox->ext_header_rewrite = TRUE;
	}

	mbox->highest_mailbox_id = ext_hdr == NULL ? 0 :
		ext_hdr->highest_mailbox_id;
	/* do not mark it initialized if it's broken */
	mbox->sync_initialized = !*broken_r;

	/* assign new mailbox IDs if any are missing */
	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->mailbox_id == 0) {
			bboxes[i]->mailbox_id = ++mbox->highest_mailbox_id;
			ret = 0;
		}
	}
	/* sort the backend mailboxes by mailbox_id. */
	array_sort(&mbox->backend_boxes, bbox_mailbox_id_cmp);
	if (ret == 0)
		mbox->ext_header_rewrite = TRUE;
	return ret;
}

static void virtual_sync_ext_header_rewrite(struct virtual_sync_context *ctx)
{
	struct virtual_mail_index_header ext_hdr;
	struct virtual_mail_index_mailbox_record mailbox;
	struct virtual_mail_index_mailbox_ext2_record ext2_rec;
	struct virtual_backend_box **bboxes;
	buffer_t *buf, *buf2;
	const void *ext_data;
	size_t ext_size;
	unsigned int i, mailbox_pos, name_pos, count;

	bboxes = array_get_modifiable(&ctx->mbox->backend_boxes, &count);
	mailbox_pos = sizeof(ext_hdr);
	name_pos = mailbox_pos + sizeof(mailbox) * count;

	i_zero(&ext_hdr);
	i_zero(&mailbox);
	i_zero(&ext2_rec);

	ext_hdr.change_counter = ++ctx->mbox->prev_change_counter;
	ext_hdr.mailbox_count = count;
	ext_hdr.highest_mailbox_id = ctx->mbox->highest_mailbox_id;
	ext_hdr.search_args_crc32 = ctx->mbox->search_args_crc32;

	buf = buffer_create_dynamic(default_pool, name_pos + 256);
	buffer_append(buf, &ext_hdr, sizeof(ext_hdr));

	struct virtual_mail_index_ext2_header ext2_hdr = {
		.version = VIRTUAL_MAIL_INDEX_EXT2_HEADER_VERSION,
		.ext_record_size = sizeof(struct virtual_mail_index_mailbox_ext2_record),
		.hdr_size = sizeof(struct virtual_mail_index_ext2_header),
		.change_counter = ext_hdr.change_counter,
	};
	buf2 = buffer_create_dynamic(default_pool, sizeof(ext2_hdr) +
				     sizeof(ext2_rec) * count);
	buffer_append(buf2, &ext2_hdr, sizeof(ext2_hdr));

	for (i = 0; i < count; i++) {
		i_assert(i == 0 ||
			 bboxes[i]->mailbox_id > bboxes[i-1]->mailbox_id);

		bboxes[i]->sync_mailbox_idx1 = i+1;
		mailbox.id = bboxes[i]->mailbox_id;
		mailbox.name_len = strlen(bboxes[i]->name);
		mailbox.uid_validity = bboxes[i]->sync_uid_validity;
		mailbox.highest_modseq = bboxes[i]->ondisk_highest_modseq;
		mailbox.next_uid = bboxes[i]->sync_next_uid;
		buffer_write(buf, mailbox_pos, &mailbox, sizeof(mailbox));
		buffer_write(buf, name_pos, bboxes[i]->name, mailbox.name_len);

		guid_128_copy(ext2_rec.guid, bboxes[i]->sync_guid);
		buffer_append(buf2, &ext2_rec, sizeof(ext2_rec));

		mailbox_pos += sizeof(mailbox);
		name_pos += mailbox.name_len;

		/* repair the value */
		if (ctx->mbox->highest_mailbox_id < mailbox.id)
			ctx->mbox->highest_mailbox_id = mailbox.id;
	}
	if (ctx->mbox->highest_mailbox_id != ext_hdr.highest_mailbox_id) {
		ext_hdr.highest_mailbox_id = ctx->mbox->highest_mailbox_id;
		buffer_write(buf, 0, &ext_hdr, sizeof(ext_hdr));
	}
	i_assert(buf->used == name_pos);

	/* update base extension */
	mail_index_get_header_ext(ctx->view, ctx->mbox->virtual_ext_id,
				  &ext_data, &ext_size);
	if (ext_size < name_pos) {
		mail_index_ext_resize(ctx->trans, ctx->mbox->virtual_ext_id,
				      name_pos,
				      sizeof(struct virtual_mail_index_record),
				      sizeof(uint32_t));
	}
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext_id,
				     0, buf->data, name_pos);

	/* update ext2 */
	mail_index_get_header_ext(ctx->view, ctx->mbox->virtual_ext2_id,
				  &ext_data, &ext_size);
	if (ext_size != buf2->used) {
		mail_index_ext_resize(ctx->trans, ctx->mbox->virtual_ext2_id,
				      buf2->used, 0, 0);
	}
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext2_id,
				     0, buf2->data, buf2->used);
	buffer_free(&buf);
	buffer_free(&buf2);
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
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext2_id,
		offsetof(struct virtual_mail_index_ext2_header, change_counter),
		&ext_hdr.change_counter, sizeof(ext_hdr.change_counter));
}

static void
virtual_sync_gather_index_rec(struct virtual_mailbox *mbox,
			      struct mail_index_view *sync_view,
			      const char *const *kw_all,
			      const struct mail_index_sync_rec *sync_rec,
			      pool_t pool,
			      ARRAY_TYPE(virtual_backend_change) *changes)
{
	uint32_t virtual_ext_id = mbox->virtual_ext_id;
	struct virtual_backend_box *bbox;
	const struct virtual_mail_index_record *vrec;
	struct virtual_backend_change *change;
	const void *data;
	uint32_t vseq, seq1, seq2;

	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		break;
	}
	if (!mail_index_lookup_seq_range(sync_view, sync_rec->uid1,
					 sync_rec->uid2, &seq1, &seq2)) {
		/* already expunged, nothing to do. */
		return;
	}

	for (vseq = seq1; vseq <= seq2; vseq++) {
		mail_index_lookup_ext(sync_view, vseq, virtual_ext_id,
				      &data, NULL);
		vrec = data;

		if (!virtual_backend_box_lookup(mbox, vrec->mailbox_id, &bbox))
			continue;

		change = array_append_space(changes);
		change->idx = array_count(changes) - 1;
		change->bbox = bbox;
		change->real_uid = vrec->real_uid;
		change->type = sync_rec->type;
		switch (sync_rec->type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			change->add_flags =
				sync_rec->add_flags & MAIL_FLAGS_NONRECENT;
			change->remove_flags =
				sync_rec->remove_flags & MAIL_FLAGS_NONRECENT;
			break;
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
			change->keyword =
				p_strdup(pool, kw_all[sync_rec->keyword_idx]);
			break;
		}
	}
}

static int
virtual_backend_change_cmp(const struct virtual_backend_change *c1,
			   const struct virtual_backend_change *c2)
{
	if (c1->bbox->mailbox_id < c2->bbox->mailbox_id)
		return -1;
	if (c1->bbox->mailbox_id > c2->bbox->mailbox_id)
		return 1;
	if (c1->real_uid < c2->real_uid)
		return -1;
	if (c1->real_uid > c2->real_uid)
		return 1;
	/* the changes to the same mail must stay in the same order */
	if (c1->idx < c2->idx)
		return -1;
	if (c1->idx > c2->idx)
		return 1;
	return 0;
}

static void
virtual_sync_gather_changes(struct virtual_mailbox *mbox,
			    struct mail_index_sync_ctx *index_sync_ctx,
			    struct mail_index_view *sync_view, pool_t pool,
			    ARRAY_TYPE(virtual_backend_change) *changes)
{
	const ARRAY_TYPE(keywords) *keywords;
	const char *const *kw_all;
	struct mail_index_sync_rec sync_rec;

	keywords = mail_index_get_keywords(mbox->box.index);
	kw_all = array_count(keywords) == 0 ? NULL : array_front(keywords);
	while (mail_index_sync_next(index_sync_ctx, &sync_rec)) {
		virtual_sync_gather_index_rec(mbox, sync_view, kw_all,
					      &sync_rec, pool, changes);
	}
	/* Apply the changes one backend mailbox at a time, and in UID order
	   within the mailbox. The sync records were gathered in virtual UID
	   order, which can map to backend mailboxes in any order. */
	array_sort(changes, virtual_backend_change_cmp);
}

static int
virtual_sync_apply_backend_change(struct virtual_mailbox *mbox,
				  const struct virtual_backend_change *change)
{
	struct virtual_backend_box *bbox = change->bbox;
	struct mail_keywords *keywords;
	enum modify_type modify_type;
	const char *kw_names[2];

	if (!bbox->box->opened) {
		if (virtual_backend_box_open(mbox, bbox) < 0) {
			virtual_box_copy_error(&mbox->box, bbox->box);
			return -1;
		}
	} else {
		virtual_backend_box_accessed(mbox, bbox);
	}

	virtual_backend_box_sync_mail_set(bbox);
	if (!mail_set_uid(bbox->sync_mail, change->real_uid)) {
		/* message is already expunged from backend mailbox. */
		return 0;
	}

	switch (change->type) {
	case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
		mail_expunge(bbox->sync_mail);
		break;
	case MAIL_INDEX_SYNC_TYPE_FLAGS:
		if (change->add_flags != 0) {
			mail_update_flags(bbox->sync_mail, MODIFY_ADD,
					  change->add_flags);
		}
		if (change->remove_flags != 0) {
			mail_update_flags(bbox->sync_mail, MODIFY_REMOVE,
					  change->remove_flags);
		}
		break;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		kw_names[0] = change->keyword;
		kw_names[1] = NULL;
		keywords = mailbox_keywords_create_valid(bbox->box, kw_names);

		modify_type = change->type == MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD ?
			MODIFY_ADD : MODIFY_REMOVE;
		mail_update_keywords(bbox->sync_mail, modify_type, keywords);
		mailbox_keywords_unref(&keywords);
		break;
	}
	return 0;
}

/* Apply the changes to the backend mailboxes and commit the backend
   transactions. */
static int
virtual_sync_apply_backend_changes(struct virtual_mailbox *mbox,
				   const ARRAY_TYPE(virtual_backend_change) *changes)
{
	const struct virtual_backend_change *change;
	struct virtual_backend_box *bbox;
	int ret = 0;

	array_foreach(changes, change) {
		if (virtual_sync_apply_backend_change(mbox, change) < 0) {
			ret = -1;
			break;
		}
	}
	array_foreach_elem(&mbox->backend_boxes, bbox)
		virtual_backend_box_sync_mail_unset(bbox);
	return ret;
}

/* Apply the virtual index's changes (expunges, flag and keyword changes) to
   the backend mailboxes. The changes are read without locking the virtual
   index, and its sync is rolled back. The following sync commits the
   changes up to the returned transaction log position, which marks them
   synced. The changes after it are left for the next sync.

   The backend mailboxes are accessed while the virtual index isn't locked.
   Committing changes to them can take a long time, and e.g. with obox it
   can lock the metacache upload lock, while another process may be holding
   it and waiting for the virtual index's transaction log lock. */
static int
virtual_sync_apply_index_changes(struct virtual_mailbox *mbox,
				 uint32_t *log_seq_r, uoff_t *log_offset_r)
{
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	ARRAY_TYPE(virtual_backend_change) changes;
	uint32_t seq1;
	uoff_t offset1;
	pool_t pool;
	bool broken;
	int ret;

	if (mail_index_sync_begin(mbox->box.index, &index_sync_ctx,
				  &sync_view, &trans,
				  MAIL_INDEX_SYNC_FLAG_READ_ONLY) < 0) {
		mailbox_set_index_error(&mbox->box);
		return -1;
	}
	/* The backend mailboxes are looked up by their mailbox_ids, which
	   come from the header. Brokenness is handled later by the sync. */
	if (virtual_mailbox_ext_header_read(mbox, sync_view, &broken) < 0) {
		mail_index_sync_rollback(&index_sync_ctx);
		return -1;
	}

	pool = pool_alloconly_create("virtual sync changes", 1024);
	p_array_init(&changes, pool, 16);
	virtual_sync_gather_changes(mbox, index_sync_ctx, sync_view,
				    pool, &changes);
	mail_index_sync_get_offsets(index_sync_ctx, &seq1, &offset1,
				    log_seq_r, log_offset_r);
	mail_index_sync_rollback(&index_sync_ctx);

	ret = virtual_sync_apply_backend_changes(mbox, &changes);
	pool_unref(&pool);
	return ret;
}

static void virtual_sync_index_finish(struct virtual_sync_context *ctx)
{
	struct mailbox *box = &ctx->mbox->box;
	const struct mail_index_header *hdr;
	struct mail_index_view *view;
	uint32_t seq1, seq2;

	view = mail_index_transaction_open_updated_view(ctx->trans);

	hdr = mail_index_get_header(ctx->view);
	if (hdr->uid_validity != 0)
		ctx->uid_validity = hdr->uid_validity;
	else
		virtual_sync_set_uidvalidity(ctx);

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(view, hdr->first_recent_uid,
					UINT32_MAX, &seq1, &seq2)) {
		mailbox_recent_flags_set_seqs(&ctx->mbox->box, view,
					      seq1, seq2);
	}

	mail_index_view_close(&view);

	if (ctx->mbox->ext_header_rewrite) {
		/* entire mailbox list needs to be rewritten */
		virtual_sync_ext_header_rewrite(ctx);
	} else {
		/* update only changed parts in the header */
		virtual_sync_ext_header_update(ctx);
	}

	mailbox_sync_notify(box, 0, 0);
}

static int virtual_sync_backend_box_init(struct virtual_backend_box *bbox)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct virtual_backend_uidmap uidmap;
	enum mailbox_search_result_flags result_flags;
	int ret;

	trans = mailbox_transaction_begin(bbox->box, 0, __func__);

	if (!bbox->search_args_initialized) {
		mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);
		bbox->search_args_initialized = TRUE;
	}
	search_ctx = mailbox_search_init(trans, bbox->search_args, NULL,
					 0, NULL);

	/* save the result and keep it updated */
	result_flags = MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
		MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC;
	bbox->search_result =
		mailbox_search_result_save(search_ctx, result_flags);

	/* add the found UIDs to uidmap. virtual_uid gets assigned later. */
	i_zero(&uidmap);
	array_clear(&bbox->uids);
	while (mailbox_search_next(search_ctx, &mail)) {
		uidmap.real_uid = mail->uid;
		array_push_back(&bbox->uids, &uidmap);
	}
	ret = mailbox_search_deinit(&search_ctx);

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
			if (uidmap[src].virtual_uid == 0) {
				/* has not been assigned yet */
				continue;
			}
			if (mail_index_lookup_seq(ctx->view,
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
	i_zero(&rec);
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
				array_push_back(&ctx->all_adds, &rec);
			}
		}
	}
}

static void
virtual_sync_mailbox_box_update_flags(struct virtual_sync_context *ctx,
				      struct virtual_backend_box *bbox,
				      const ARRAY_TYPE(seq_range) *uids_arr)
{
	unsigned int i, uid, vseq;
	const struct virtual_backend_uidmap *vuid;
	struct seq_range_iter iter;

	i = 0;
	seq_range_array_iter_init(&iter, uids_arr);
	while(seq_range_array_iter_nth(&iter, i++, &uid)) {
		vuid = array_bsearch(&bbox->uids, &uid,
				     virtual_backend_uidmap_bsearch_cmp);
		if (vuid == NULL ||
		    vuid->virtual_uid == 0 ||
		    !mail_index_lookup_seq(ctx->view,
					   vuid->virtual_uid, &vseq)) {
			/* the entry has been already removed either by
			   us or some other session. doesn't matter,
			   we don't need to update the flags.

			   it might also have not yet been assigned a uid
			   so we don't want to update the flags then either.
			*/
			continue;
		}
		virtual_sync_external_flags(ctx, bbox, vseq,
					    vuid->real_uid);
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
virtual_sync_backend_add_vmsgs_results(struct virtual_sync_context *ctx,
				       struct virtual_backend_box *bbox,
                                       uint32_t real_uid,
                                       struct mail_search_result *result,
                                       const uint32_t vseq)
{
	struct virtual_backend_uidmap uidmap;
	uint32_t vuid, seq;

	mail_index_lookup_uid(ctx->view, vseq, &vuid);

	i_zero(&uidmap);
	uidmap.real_uid = real_uid;
	uidmap.virtual_uid = vuid;
	array_push_back(&bbox->uids, &uidmap);

	if (result == NULL)
		;
	else if (mail_index_lookup_seq(bbox->box->view, real_uid, &seq))
		seq_range_array_add(&result->uids, real_uid);
	else
		seq_range_array_add(&result->removed_uids, real_uid);
}

static void
virtual_sync_backend_handle_old_vmsgs(struct virtual_sync_context *ctx,
				      struct virtual_backend_box *bbox,
				      struct mail_search_result *result)
{
	const struct virtual_mail_index_record *vrec;
	const struct virtual_sync_mail *sync_mail, *sync_mails;
	const void *data;
	uint32_t i, vseq, messages;

	/* find the messages that currently exist in virtual index and add them
	   to the backend mailbox's list of uids. */
	array_clear(&bbox->uids);

	if (array_is_created(&ctx->all_mails)) {
		i_assert(ctx->all_mails_prev_mailbox_id < bbox->mailbox_id);
		sync_mails = array_get(&ctx->all_mails, &messages);
		for (i = ctx->all_mails_idx; i < messages; i++) {
			sync_mail = &sync_mails[i];
			if (sync_mail->vrec.mailbox_id != bbox->mailbox_id) {
				if (sync_mail->vrec.mailbox_id < bbox->mailbox_id) {
					/* stale mailbox_id, ignore */
					continue;
				}
				/* Should be in mailbox_id order,
				   so skip to next box */
				break;
			}

			virtual_sync_backend_add_vmsgs_results(ctx, bbox,
				sync_mail->vrec.real_uid, result, sync_mail->vseq);
		}
		ctx->all_mails_idx = i;
		ctx->all_mails_prev_mailbox_id = bbox->mailbox_id;
	} else {
		/* there should be only a single backend mailbox, but in the
		   existing index there may be stale mailbox_ids that we'll
		   just skip over. */
		messages = mail_index_view_get_messages_count(ctx->view);
		for (vseq = 1; vseq <= messages; vseq++) {
			mail_index_lookup_ext(ctx->view, vseq,
			                      ctx->mbox->virtual_ext_id, &data, NULL);
			vrec = data;
			if (vrec->mailbox_id == bbox->mailbox_id) {
				virtual_sync_backend_add_vmsgs_results(ctx,
					bbox, vrec->real_uid, result, vseq);
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
	ARRAY_TYPE(seq_range) expunged_uids = ARRAY_INIT, removed_uids;
	ARRAY_TYPE(seq_range) added_uids, flag_update_uids;
	uint64_t modseq, old_highest_modseq;
	uint32_t seq, uid, old_msg_count;

	/* initialize the search result from all the existing messages in
	   virtual index. */
	if (!bbox->search_args_initialized) {
		mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);
		bbox->search_args_initialized = TRUE;
	}
	result = mailbox_search_result_alloc(bbox->box, bbox->search_args,
					     result_flags);
	mailbox_search_result_initial_done(result);
	i_assert(array_count(&result->removed_uids) == 0);
	virtual_sync_backend_handle_old_vmsgs(ctx, bbox, result);
	if (array_count(&result->removed_uids) > 0) {
		/* these are all expunged messages. treat them separately from
		   "no longer matching messages" (=removed_uids) */
		t_array_init(&expunged_uids, array_count(&result->removed_uids));
		array_append_array(&expunged_uids, &result->removed_uids);
		array_clear(&result->removed_uids);
	}

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
				seq_range_array_add(&flag_update_uids, uid);
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
	if (array_is_created(&expunged_uids)) {
		seq_range_array_remove_seq_range(&removed_uids, &expunged_uids);
		virtual_sync_mailbox_box_remove(ctx, bbox, &expunged_uids);
	}
	if (ctx->expunge_removed)
		virtual_sync_mailbox_box_remove(ctx, bbox, &removed_uids);
	else {
		/* delayed remove */
		seq_range_array_merge(&bbox->sync_pending_removes,
				      &removed_uids);
	}
	virtual_sync_mailbox_box_add(ctx, bbox, &added_uids);
	virtual_sync_mailbox_box_update_flags(ctx, bbox, &flag_update_uids);

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
			seq_range_array_add(&drop_uids, add_uid);
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
			seq_range_array_add(&drop_uids, remove_uid);
		else
			i++;
		if (!seq_range_array_iter_nth(&iter, n++, &remove_uid)) {
			iter_done = TRUE;
			break;
		}
	}
	if (!iter_done) {
		do {
			seq_range_array_add(&drop_uids, remove_uid);
		} while (seq_range_array_iter_nth(&iter, n++, &remove_uid));
	}
	seq_range_array_remove_seq_range(removed_uids, &drop_uids);
}

static void virtual_sync_mailbox_box_update(struct virtual_sync_context *ctx,
					    struct virtual_backend_box *bbox)
{
	ARRAY_TYPE(seq_range) removed_uids, added_uids, temp_uids;
	unsigned int count1, count2;

	i_assert(bbox->search_result != NULL);

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
		seq_range_array_add(&ctx->sync_expunges, uidmap[i].real_uid);
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
			uidmap = array_front(&bbox->uids);
			for (; idx1 <= idx2; idx1++) {
				vuid = uidmap[idx1].virtual_uid;
				if (vuid == 0) {
					/* has not been even assigned yet */
					continue;
				}
				if (!mail_index_lookup_seq(ctx->view,
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
	if (mailbox_sync_deinit(&sync_ctx, &sync_status) < 0) {
		if (mailbox_get_last_mail_error(bbox->box) != MAIL_ERROR_NOTFOUND)
			return -1;
		/* mailbox was deleted */
		virtual_sync_backend_box_deleted(ctx, bbox);
		return 0;
	}
	return 0;
}

static bool
virtual_bbox_mailbox_equals(struct virtual_backend_box *bbox,
			    const struct mailbox_status *status,
			    struct mailbox_metadata *metadata,
			    const char **reason_r)
{
	if (!guid_128_equals(bbox->sync_guid, metadata->guid)) {
		*reason_r = t_strdup_printf("GUID changed: %s -> %s",
					    guid_128_to_string(bbox->sync_guid),
					    guid_128_to_string(metadata->guid));
		return FALSE;
	}
	if (bbox->sync_uid_validity != status->uidvalidity) {
		*reason_r = t_strdup_printf("UIDVALIDITY changed: %u -> %u",
			bbox->sync_uid_validity, status->uidvalidity);
		return FALSE;
	}
	if (bbox->sync_next_uid != status->uidnext) {
		*reason_r = t_strdup_printf("UIDNEXT changed: %u -> %u",
			bbox->sync_next_uid, status->uidnext);
		return FALSE;
	}
	if (bbox->sync_highest_modseq != status->highest_modseq) {
		*reason_r = t_strdup_printf("HIGHESTMODSEQ changed: "
			"%"PRIu64" -> %"PRIu64,
			bbox->sync_highest_modseq, status->highest_modseq);
		return FALSE;
	}
	return TRUE;
}

static void virtual_sync_backend_ext_header(struct virtual_sync_context *ctx,
					    struct virtual_backend_box *bbox)
{
	const unsigned int uidval_pos =
		offsetof(struct virtual_mail_index_mailbox_record,
			 uid_validity);
	struct mailbox_status status;
	struct virtual_mail_index_mailbox_record mailbox;
	struct virtual_mail_index_mailbox_ext2_record ext2;
	unsigned int mailbox_offset, ext2_offset;
	uint64_t wanted_ondisk_highest_modseq;
	struct mailbox_metadata metadata;
	const char *reason;

	mailbox_get_open_status(bbox->box, STATUS_UIDVALIDITY |
				STATUS_HIGHESTMODSEQ, &status);
	wanted_ondisk_highest_modseq =
		array_count(&bbox->sync_pending_removes) > 0 ? 0 :
		status.highest_modseq;

	if (mailbox_get_metadata(bbox->box, MAILBOX_METADATA_GUID,
				 &metadata) < 0) {
		/* Either a temporary failure or the mailbox was already
		   deleted. Either way, it doesn't really matter at this point.
		   We'll just leave the error handling until the next sync. */
		return;
	}

	if (virtual_bbox_mailbox_equals(bbox, &status, &metadata, &reason) &&
	    bbox->ondisk_highest_modseq == wanted_ondisk_highest_modseq)
		return;

	/* mailbox changed - update extension header */
	bbox->sync_uid_validity = status.uidvalidity;
	bbox->sync_highest_modseq = status.highest_modseq;
	bbox->ondisk_highest_modseq = wanted_ondisk_highest_modseq;
	bbox->sync_next_uid = status.uidnext;
	guid_128_copy(bbox->sync_guid, metadata.guid);

	if (ctx->mbox->ext_header_rewrite) {
		/* we'll rewrite the entire header later */
		return;
	}

	i_zero(&mailbox);
	mailbox.uid_validity = bbox->sync_uid_validity;
	mailbox.highest_modseq = bbox->ondisk_highest_modseq;
	mailbox.next_uid = bbox->sync_next_uid;

	i_zero(&ext2);
	guid_128_copy(ext2.guid, bbox->sync_guid);

	i_assert(bbox->sync_mailbox_idx1 > 0);
	mailbox_offset = sizeof(struct virtual_mail_index_header) +
		(bbox->sync_mailbox_idx1-1) * sizeof(mailbox);
	ext2_offset = sizeof(struct virtual_mail_index_ext2_header) +
		(bbox->sync_mailbox_idx1-1) * sizeof(ext2);
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext_id,
				     mailbox_offset + uidval_pos,
				     CONST_PTR_OFFSET(&mailbox, uidval_pos),
				     sizeof(mailbox) - uidval_pos);
	mail_index_update_header_ext(ctx->trans, ctx->mbox->virtual_ext2_id,
				     ext2_offset, &ext2, sizeof(ext2));
	ctx->ext_header_changed = TRUE;
}

static void virtual_sync_backend_box_deleted(struct virtual_sync_context *ctx,
					     struct virtual_backend_box *bbox)
{
	ARRAY_TYPE(seq_range) removed_uids;
	const struct virtual_backend_uidmap *uidmap;

	/* delay its full removal until the next time we open the virtual
	   mailbox. for now just treat it as if it was empty. */

	t_array_init(&removed_uids, 128);
	array_foreach(&bbox->uids, uidmap)
		seq_range_array_add(&removed_uids, uidmap->real_uid);
	virtual_sync_mailbox_box_remove(ctx, bbox, &removed_uids);

	bbox->deleted = TRUE;
}

static bool
virtual_backend_box_is_uncreated(struct virtual_backend_box *bbox)
{
	/* The mailbox doesn't exist, but it's autocreated the next time it's
	   accessed outside syncing. Don't treat it as a deleted mailbox. */
	return mailbox_is_autocreated(bbox->box);
}

static int
virtual_try_open_and_sync_backend_box(struct virtual_sync_context *ctx,
				      struct virtual_backend_box *bbox,
				      enum mailbox_sync_flags sync_flags)
{
	int ret = 0;

	if (!bbox->box->opened)
		ret = virtual_backend_box_open(ctx->mbox, bbox);
	if (ret == 0)
		ret = mailbox_sync(bbox->box, sync_flags);
	if (ret < 0) {
		if (mailbox_get_last_mail_error(bbox->box) != MAIL_ERROR_NOTFOUND)
			return -1;
		if (virtual_backend_box_is_uncreated(bbox))
			return 0;
		/* mailbox was deleted */
		virtual_sync_backend_box_deleted(ctx, bbox);
		return 0;
	}
	return 1;
}

static int virtual_sync_backend_box(struct virtual_sync_context *ctx,
				    struct virtual_backend_box *bbox)
{
	enum mailbox_sync_flags sync_flags;
	struct mailbox_status status;
	const char *reason;
	int ret;

	if (bbox->deleted)
		return 0;

	/* if we already did some changes to index, commit them before
	   syncing starts. */
	virtual_backend_box_sync_mail_unset(bbox);

	sync_flags = ctx->flags & (MAILBOX_SYNC_FLAG_FULL_READ |
				   MAILBOX_SYNC_FLAG_FAST);

	if (bbox->search_result == NULL) {
		struct mailbox_metadata metadata;

		/* a) first sync in this process.
		   b) we had auto-closed this backend mailbox.

		   first try to quickly check if the mailbox has changed.
		   if we can do that check from mailbox list index, we don't
		   even need to open the mailbox. */
		i_assert(array_count(&bbox->sync_pending_removes) == 0);
		if (bbox->box->opened || bbox->open_failed) {
			/* a) index already opened, refresh it
			   b) delayed error handling for mailbox_open()
			   that failed in virtual_notify_changes() */
			if ((ret = virtual_try_open_and_sync_backend_box(ctx, bbox, sync_flags)) <= 0)
				return ret;
			bbox->open_failed = FALSE;
		}

		if ((mailbox_get_status(bbox->box, STATUS_UIDVALIDITY |
				       STATUS_UIDNEXT | STATUS_HIGHESTMODSEQ,
				       &status) < 0) ||
		    (mailbox_get_metadata(bbox->box, MAILBOX_METADATA_GUID,
					  &metadata) < 0)) {
			if (mailbox_get_last_mail_error(bbox->box) != MAIL_ERROR_NOTFOUND)
				return -1;
			if (virtual_backend_box_is_uncreated(bbox))
				return 0;
			/* mailbox was deleted */
			virtual_sync_backend_box_deleted(ctx, bbox);
			return 0;
		}
		if (guid_128_is_empty(bbox->sync_guid)) {
			/* upgrading from old virtual index */
			guid_128_copy(bbox->sync_guid, metadata.guid);
			ctx->mbox->ext_header_rewrite = TRUE;
		}
		if (virtual_bbox_mailbox_equals(bbox, &status, &metadata, &reason)) {
			/* mailbox hasn't changed since we last opened it,
			   skip it for now.

			   we'll still need to create the bbox->uids mapping
			   using the current index. */
			if (array_count(&bbox->uids) == 0)
				virtual_sync_backend_handle_old_vmsgs(ctx, bbox, NULL);
			return 0;
		}
		e_debug(ctx->mbox->box.event, "Backend mailbox %s changed: %s",
			bbox->box->vname, reason);
		if (!bbox->box->opened) {
			/* first time we're opening the index */
			if ((ret = virtual_try_open_and_sync_backend_box(ctx, bbox, sync_flags)) <= 0)
				return ret;
		}

		virtual_backend_box_sync_mail_set(bbox);
		if ((status.uidvalidity != bbox->sync_uid_validity) ||
		    !guid_128_equals(metadata.guid, bbox->sync_guid)) {
			/* UID validity or GUID changed since last sync (or
			   this is the first sync), do a full search */
			bbox->first_sync = TRUE;
			ret = virtual_sync_backend_box_init(bbox);
		} else {
			/* build the initial search using the saved modseq. */
			ret = virtual_sync_backend_box_continue(ctx, bbox);
		}
		i_assert(bbox->search_result != NULL || ret < 0);
	} else {
		/* sync using the existing search result */
		i_assert(bbox->box->opened);
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
	uint32_t i, vseq, vuid, messages;
	unsigned int j = 0, uidmap_count = 0;

	messages = mail_index_view_get_messages_count(ctx->view);
	if (messages == 0)
		return;

	/* sort the messages in current view by their backend mailbox and
	   real UID */
	vmails = i_new(struct virtual_sync_mail, messages);
	for (vseq = 1; vseq <= messages; vseq++) {
		mail_index_lookup_ext(ctx->view, vseq, virtual_ext_id,
				      &data, NULL);
		vrec = data;
		vmails[vseq-1].vseq = vseq;
		vmails[vseq-1].vrec = *vrec;
	}
	qsort(vmails, messages, sizeof(*vmails), virtual_sync_mail_uid_cmp);

	/* create real mailbox uid -> virtual uid mapping and expunge
	   messages no longer matching the search rule */
	i_zero(&add_rec);
	bbox = NULL;
	for (i = 0; i < messages; i++) {
		vseq = vmails[i].vseq;
		vrec = &vmails[i].vrec;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			/* add the rest of the newly seen messages */
			for (; j < uidmap_count; j++) {
				add_rec.rec.real_uid = uidmap[j].real_uid;
				array_push_back(&ctx->all_adds, &add_rec);
			}
			if (!virtual_backend_box_lookup(ctx->mbox,
							vrec->mailbox_id,
							&bbox) ||
			    bbox->first_sync) {
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
		mail_index_lookup_uid(ctx->view, vseq, &vuid);

		/* if virtual record doesn't exist in uidmap, it's expunged */
		for (; j < uidmap_count; j++) {
			if (uidmap[j].real_uid >= vrec->real_uid)
				break;

			/* newly seen message */
			add_rec.rec.real_uid = uidmap[j].real_uid;
			array_push_back(&ctx->all_adds, &add_rec);
		}
		if (j == uidmap_count || uidmap[j].real_uid != vrec->real_uid)
			mail_index_expunge(ctx->trans, vseq);
		else {
			/* exists - update uidmap and flags */
			uidmap[j++].virtual_uid = vuid;
			if (bbox->search_result == NULL) {
				/* mailbox is completely unchanged since last
				   sync - no need to sync flags */
			} else {
				virtual_sync_external_flags(ctx, bbox, vseq,
							    vrec->real_uid);
			}
		}
	}
	i_free(vmails);

	/* finish adding messages to the last mailbox */
	for (; j < uidmap_count; j++) {
		add_rec.rec.real_uid = uidmap[j].real_uid;
		array_push_back(&ctx->all_adds, &add_rec);
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
	i_zero(&add_rec);
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		bboxes[i]->first_sync = FALSE; /* this is the end of the sync */

		if (bboxes[i]->sync_seen)
			continue;

		add_rec.rec.mailbox_id = bboxes[i]->mailbox_id;
		uidmap = array_get_modifiable(&bboxes[i]->uids, &uidmap_count);
		for (j = 0; j < uidmap_count; j++) {
			add_rec.rec.real_uid = uidmap[j].real_uid;
			array_push_back(&ctx->all_adds, &add_rec);
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

static int virtual_sync_backend_sort_new(struct virtual_sync_context *ctx)
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
			/* The mailbox_id comes from ctx->all_adds, which is
			   filled earlier in this sync. The mailbox_ids in it
			   come via mbox->backend_boxes, so the backend box is
			   guaranteed to have existed already in this sync.
			   Since backend_boxes are never removed during the sync,
			   the lookup is guaranteed to find it here.
			   (backend_boxes removal is done only while opening
			   the virtual mailbox in virtual_mailbox_open() ) */
			if (!virtual_backend_box_lookup(ctx->mbox,
							vrec->mailbox_id, &bbox))
				   i_unreached();
			if (!bbox->box->opened &&
			    virtual_backend_box_open(ctx->mbox, bbox) < 0) {
				virtual_box_copy_error(&ctx->mbox->box,
						       bbox->box);
				return -1;
			}
			virtual_backend_box_sync_mail_set(bbox);
		}
		if (!mail_set_uid(bbox->sync_mail, vrec->real_uid)) {
			/* we may have reopened the mailbox, which could have
			   caused the mail to be expunged already. */
			adds[i].received_date = 0;
		} else if (mail_get_received_date(bbox->sync_mail,
						  &adds[i].received_date) < 0) {
			enum mail_error error =
				mailbox_get_last_mail_error(bbox->box);

			if (!bbox->sync_mail->expunged &&
			    error != MAIL_ERROR_NOTFOUND) {
				virtual_box_copy_error(&ctx->mbox->box,
						       bbox->box);
				return -1;
			}
			/* Expunged already, or the mailbox was deleted under
			   us. Just add it somewhere - the mails are removed
			   from the virtual mailbox by the next sync. */
			adds[i].received_date = 0;
		}
	}

	array_sort(&ctx->all_adds, virtual_add_record_cmp);
	return 0;
}

static int virtual_sync_backend_add_new(struct virtual_sync_context *ctx)
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

	hdr = mail_index_get_header(ctx->view);
	adds = array_get_modifiable(&ctx->all_adds, &count);
	if (count == 0) {
		ctx->mbox->sync_virtual_next_uid = hdr->next_uid;
		return 0;
	}

	if (adds[0].rec.mailbox_id == adds[count-1].rec.mailbox_id) {
		/* all messages are from a single mailbox. add them in
		   the same order. */
	} else {
		/* sort new messages by received date to get the add order */
		if (virtual_sync_backend_sort_new(ctx) < 0)
			return -1;
	}

	for (bbox = NULL, i = 0; i < count; i++) {
		vrec = &adds[i].rec;
		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			if (!virtual_backend_box_lookup(ctx->mbox,
							vrec->mailbox_id, &bbox)) {
				/* See virtual_sync_backend_sort_new() */
				i_unreached();
			}
			if (!bbox->box->opened &&
			    virtual_backend_box_open(ctx->mbox, bbox) < 0) {
				virtual_box_copy_error(&ctx->mbox->box,
						       bbox->box);
				return -1;
			}
			virtual_backend_box_sync_mail_set(bbox);
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
			if (!virtual_backend_box_lookup(ctx->mbox,
							vrec->mailbox_id, &bbox)) {
				/* See virtual_sync_backend_sort_new() */
				i_unreached();
			}

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
	return 0;
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
	uint32_t seq, seq2;

	if (!ctx->mbox->uids_mapped)
		return 0;

	hdr = mail_index_get_header(ctx->view);
	if (ctx->mbox->sync_virtual_next_uid >= hdr->next_uid)
		return 0;

	/* another process added messages to virtual index. get backend boxes'
	   uid lists up-to-date by adding the new messages there. */
	if (!mail_index_lookup_seq_range(ctx->view,
					 ctx->mbox->sync_virtual_next_uid,
					 UINT32_MAX, &seq, &seq2))
		return 0;

	i_zero(&uidmap);
	for (; seq <= seq2; seq++) {
		mail_index_lookup_ext(ctx->view, seq, virtual_ext_id,
				      &data, NULL);
		vrec = data;
		uidmap.real_uid = vrec->real_uid;
		mail_index_lookup_uid(ctx->view, seq, &uidmap.virtual_uid);

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			if (!virtual_backend_box_lookup(ctx->mbox,
							vrec->mailbox_id, &bbox)) {
				mail_index_expunge(ctx->trans, seq);
				continue;
			}
		}
		array_push_back(&bbox->uids, &uidmap);
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
		container_of(sync_ctx, struct index_mailbox_sync_context, ctx);
	struct virtual_backend_box *bbox = NULL;
	struct seq_range_iter iter;
	const struct virtual_mail_index_record *vrec;
	const void *data;
	unsigned int n = 0;
	uint32_t seq;

	if (isync_ctx->expunges == NULL)
		return;

	seq_range_array_iter_init(&iter, isync_ctx->expunges);
	while (seq_range_array_iter_nth(&iter, n++, &seq)) {
		mail_index_lookup_ext(mbox->box.view, seq,
				      mbox->virtual_ext_id, &data, NULL);
		vrec = data;

		if (bbox == NULL || bbox->mailbox_id != vrec->mailbox_id) {
			if (!virtual_backend_box_lookup(mbox,
							vrec->mailbox_id, &bbox))
				continue;
			if (!array_is_created(&bbox->sync_outside_expunges))
				i_array_init(&bbox->sync_outside_expunges, 32);
		}
		seq_range_array_add(&bbox->sync_outside_expunges,
				    vrec->real_uid);
	}
}

static void virtual_sync_deinit(struct virtual_sync_context **_ctx)
{
	struct virtual_sync_context *ctx = *_ctx;
	if (ctx == NULL)
		return;
	*_ctx = NULL;

	array_free(&ctx->sync_expunges);
	array_free(&ctx->replaced_flag_uids);
	array_free(&ctx->all_adds);
	array_free(&ctx->all_mails);
	i_free(ctx);
}

static int virtual_sync_mail_mailbox_cmp(const struct virtual_sync_mail *m1,
					 const struct virtual_sync_mail *m2)
{
	if (m1->vrec.mailbox_id < m2->vrec.mailbox_id)
		return -1;
	if (m1->vrec.mailbox_id > m2->vrec.mailbox_id)
		return 1;
	return 0;
}

static int virtual_sync_bboxes_get_mails(struct virtual_sync_context *ctx)
{
	uint32_t messages, vseq, vuid, prev_vuid = 0;
	const void *mail_data;
	const struct virtual_mail_index_record *vrec;
	struct virtual_sync_mail *sync_mail;

	messages = mail_index_view_get_messages_count(ctx->view);
	i_array_init(&ctx->all_mails, messages);
	for (vseq = 1; vseq <= messages; vseq++) {
		mail_index_lookup_uid(ctx->view, vseq, &vuid);
		if (vuid <= prev_vuid) {
			mail_storage_set_critical(ctx->mbox->box.storage,
				"Corrupted virtual index: uid=%u followed by uid=%u",
				prev_vuid, vuid);
			mail_index_mark_corrupted(ctx->mbox->box.index);
			return -1;
		}
		prev_vuid = vuid;

		mail_index_lookup_ext(ctx->view, vseq,
				      ctx->mbox->virtual_ext_id, &mail_data, NULL);
		vrec = mail_data;
		sync_mail = array_append_space(&ctx->all_mails);
		sync_mail->vseq = vseq;
		sync_mail->vrec = *vrec;
	}
	array_sort(&ctx->all_mails, virtual_sync_mail_mailbox_cmp);
	return 0;
}

static int virtual_sync_backend_boxes(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;
	int ret;

	if (virtual_sync_apply_existing_appends(ctx) < 0)
		return -1;

	i_array_init(&ctx->all_adds, 128);
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);

	/* we have different optimizations depending on whether the virtual
	   mailbox consists of multiple backend boxes or just one */
	if (count > 1) {
		if (virtual_sync_bboxes_get_mails(ctx) < 0)
			return -1;
	}

	for (i = 0; i < count; i++) {
		struct virtual_backend_box *bbox = bboxes[i];
		if (bbox->box->mailbox_deleted)
			continue;

		T_BEGIN {
			ret = virtual_sync_backend_box(ctx, bbox);
		} T_END;
		if (ret < 0) {
			/* backend failed, copy the error */
			virtual_box_copy_error(&ctx->mbox->box, bbox->box);
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
	ret = virtual_sync_backend_add_new(ctx);
#ifdef DEBUG
	for (i = 0; i < count; i++) {
		const struct virtual_backend_uidmap *uidmap;

		array_foreach(&bboxes[i]->uids, uidmap)
			i_assert(uidmap->virtual_uid > 0);
	}
#endif
	return ret;
}

static void virtual_sync_backend_boxes_finish(struct virtual_sync_context *ctx)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	for (i = 0; i < count; i++)
		virtual_backend_box_sync_mail_unset(bboxes[i]);
}

static void
virtual_sync_backend_boxes_set_no_autocreate(struct virtual_mailbox *mbox,
					     bool set)
{
	struct virtual_backend_box *const *bboxp;

	/* Backend mailboxes aren't autocreated while syncing. Applying the
	   virtual index's changes to a backend mailbox that was deleted in
	   the meantime must not recreate it. A backend mailbox that doesn't
	   exist is skipped by the sync instead, and it's created when it's
	   next accessed outside syncing. */
	array_foreach(&mbox->backend_boxes, bboxp) {
		if (set)
			(*bboxp)->box->flags |= MAILBOX_FLAG_NO_AUTOCREATE;
		else {
			(*bboxp)->box->flags &=
				ENUM_NEGATE(MAILBOX_FLAG_NO_AUTOCREATE);
		}
	}
}

/* Forget the in-memory sync state, which may not match the virtual index
   after a sync was rolled back. The following sync rebuilds the state from
   the virtual index, the same as when the virtual mailbox is opened. The
   mailbox_ids are kept, because mails are accessed with them also outside
   syncing. The following virtual_mailbox_ext_header_read() reassigns them
   from the header anyway. */
static void virtual_sync_reset_state(struct virtual_mailbox *mbox)
{
	struct virtual_backend_box *bbox;

	array_foreach_elem(&mbox->backend_boxes, bbox) {
		if (bbox->search_result != NULL)
			mailbox_search_result_free(&bbox->search_result);
		array_clear(&bbox->uids);
		array_clear(&bbox->sync_pending_removes);
		if (array_is_created(&bbox->sync_outside_expunges))
			array_clear(&bbox->sync_outside_expunges);

		bbox->sync_mailbox_idx1 = 0;
		bbox->sync_uid_validity = 0;
		bbox->sync_next_uid = 0;
		bbox->sync_highest_modseq = 0;
		bbox->ondisk_highest_modseq = 0;
		guid_128_empty(bbox->sync_guid);

		bbox->sync_seen = FALSE;
		bbox->uids_nonsorted = FALSE;
		bbox->deleted = FALSE;
		bbox->first_sync = FALSE;
	}
	mbox->uids_mapped = FALSE;
	mbox->sync_initialized = FALSE;
	mbox->sync_virtual_next_uid = 0;
}

static void virtual_sync_drop_recent(struct virtual_sync_context *ctx)
{
	const struct mail_index_header *hdr = mail_index_get_header(ctx->view);
	uint32_t next_uid = ctx->mbox->sync_virtual_next_uid;

	/* This is normally done by mail_index_sync_commit(), but it doesn't
	   see the messages appended by ctx->trans. */
	if (hdr->first_recent_uid < next_uid) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}
}

/* Returns -1 if the virtual index was changed in a way that doesn't allow
   committing the transaction on top of it. */
static int
virtual_sync_check_new_changes(struct virtual_sync_context *ctx,
			       struct mail_index_view *sync_view)
{
	const struct mail_index_header *hdr = mail_index_get_header(ctx->view);
	const struct mail_index_header *sync_hdr =
		mail_index_get_header(sync_view);

	/* Other sessions can only add flag and keyword changes and expunge
	   requests. Messages are added and expunged only by virtual syncs,
	   which are serialized by the virtual sync lock. */
	if (hdr->uid_validity != sync_hdr->uid_validity ||
	    hdr->next_uid != sync_hdr->next_uid ||
	    hdr->messages_count != sync_hdr->messages_count) {
		/* Messages were added or expunged by a process that doesn't
		   use the virtual sync lock. */
		mail_storage_set_error(ctx->mbox->box.storage, MAIL_ERROR_TEMP,
			"Virtual index was modified by another process during sync");
		return -1;
	}
	return 0;
}

/* Get the sequences of the messages in the UID range whose flags trans
   replaced. */
static void
virtual_sync_get_replaced_seqs(struct virtual_sync_context *ctx,
			       uint32_t uid1, uint32_t uid2,
			       ARRAY_TYPE(seq_range) *seqs)
{
	const struct seq_range *range;
	uint32_t seq1, seq2;

	array_clear(seqs);
	array_foreach(&ctx->replaced_flag_uids, range) {
		if (range->seq1 > uid2)
			break;
		if (range->seq2 < uid1)
			continue;
		if (mail_index_lookup_seq_range(ctx->view,
						I_MAX(range->seq1, uid1),
						I_MIN(range->seq2, uid2),
						&seq1, &seq2))
			seq_range_array_add_range(seqs, seq1, seq2);
	}
}

static unsigned int
virtual_sync_replay_flag_update(struct virtual_sync_context *ctx,
				const struct mail_transaction_flag_update *u,
				ARRAY_TYPE(seq_range) *seqs)
{
	enum mail_flags add_flags = u->add_flags & MAIL_INDEX_FLAGS_MASK;
	enum mail_flags remove_flags = u->remove_flags & MAIL_INDEX_FLAGS_MASK;
	const struct seq_range *range;

	virtual_sync_get_replaced_seqs(ctx, u->uid1, u->uid2, seqs);
	array_foreach(seqs, range) {
		/* Remove first. Replacing flags is done by removing all the
		   other flags and adding the wanted ones. */
		mail_index_update_flags_range(ctx->trans,
					      range->seq1, range->seq2,
					      MODIFY_REMOVE, remove_flags);
		mail_index_update_flags_range(ctx->trans,
					      range->seq1, range->seq2,
					      MODIFY_ADD, add_flags);
	}
	return array_count(seqs);
}

static void
virtual_sync_replay_keywords(struct virtual_sync_context *ctx,
			     const ARRAY_TYPE(seq_range) *seqs,
			     enum modify_type modify_type,
			     struct mail_keywords *keywords)
{
	const struct seq_range *range;
	uint32_t seq;

	array_foreach(seqs, range) {
		for (seq = range->seq1; seq <= range->seq2; seq++) {
			mail_index_update_keywords(ctx->trans, seq,
						   modify_type, keywords);
		}
	}
}

static unsigned int
virtual_sync_replay_keyword_update(
	struct virtual_sync_context *ctx,
	const struct mail_transaction_header *hdr,
	const struct mail_transaction_keyword_update *u,
	ARRAY_TYPE(seq_range) *seqs)
{
	unsigned int i, count, replayed = 0;
	const struct seq_range *uids =
		mail_transaction_keyword_update_get_uids(u, hdr->size, &count);
	const char *kw_names[2] = {
		mail_transaction_keyword_update_get_name(u),
		NULL
	};
	struct mail_keywords *keywords =
		mail_index_keywords_create(ctx->index, kw_names);

	for (i = 0; i < count; i++) {
		virtual_sync_get_replaced_seqs(ctx, uids[i].seq1, uids[i].seq2,
					       seqs);
		virtual_sync_replay_keywords(ctx, seqs, u->modify_type,
					     keywords);
		replayed += array_count(seqs);
	}
	mail_index_keywords_unref(&keywords);
	return replayed;
}

static unsigned int
virtual_sync_replay_keyword_reset(
	struct virtual_sync_context *ctx,
	const struct mail_transaction_keyword_reset *u,
	ARRAY_TYPE(seq_range) *seqs)
{
	struct mail_keywords *keywords;

	virtual_sync_get_replaced_seqs(ctx, u->uid1, u->uid2, seqs);
	if (array_count(seqs) == 0)
		return 0;
	keywords = mail_index_keywords_create(ctx->index, NULL);
	virtual_sync_replay_keywords(ctx, seqs, MODIFY_REPLACE, keywords);
	mail_index_keywords_unref(&keywords);
	return array_count(seqs);
}

/* Replay a record returned by mail_transaction_log_view_next(). It has
   already validated the record sizes and UID ranges. */
static unsigned int
virtual_sync_replay_rec(struct virtual_sync_context *ctx,
			const struct mail_transaction_header *hdr,
			const void *data, ARRAY_TYPE(seq_range) *seqs)
{
	unsigned int i, count, replayed = 0;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *u = data;

		count = hdr->size / sizeof(*u);
		for (i = 0; i < count; i++) {
			replayed += virtual_sync_replay_flag_update(ctx,
							&u[i], seqs);
		}
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
		T_BEGIN {
			replayed = virtual_sync_replay_keyword_update(ctx,
				hdr, data, seqs);
		} T_END;
		break;
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *u = data;

		count = hdr->size / sizeof(*u);
		for (i = 0; i < count; i++) {
			replayed += virtual_sync_replay_keyword_reset(ctx,
							&u[i], seqs);
		}
		break;
	}
	default:
		break;
	}
	return replayed;
}

/* Other sessions may have changed flags or keywords in the virtual index
   after the changes up to log_seq/log_offset were applied to the backend
   mailboxes. trans replaces the flags of some messages with the backend
   mailboxes' flags, which don't have these changes yet. Replay the changes
   in the same order on top of them, so committing trans doesn't revert them
   in the virtual index. The changes are applied to the backend mailboxes by
   the next sync. */
static int
virtual_sync_replay_new_flag_changes(struct virtual_sync_context *ctx)
{
	struct mail_transaction_log_view *log_view;
	const struct mail_transaction_header *hdr;
	ARRAY_TYPE(seq_range) seqs;
	const void *data;
	const char *reason;
	uint32_t head_seq;
	uoff_t head_offset;
	unsigned int replayed = 0;
	bool reset;
	int ret;

	if (!array_is_created(&ctx->replaced_flag_uids))
		return 0;

	mail_transaction_log_get_head(ctx->index->log, &head_seq, &head_offset);
	if (head_seq == ctx->log_seq && head_offset == ctx->log_offset)
		return 0;

	log_view = mail_transaction_log_view_open(ctx->index->log);
	ret = mail_transaction_log_view_set(log_view,
					    ctx->log_seq, ctx->log_offset,
					    head_seq, head_offset,
					    &reset, &reason);
	if (ret <= 0) {
		/* mail_index_sync_begin_to() already verified that
		   log_seq/log_offset is in the locked head log file, so this
		   is unexpected. */
		if (ret < 0)
			mailbox_set_index_error(&ctx->mbox->box);
		else {
			mailbox_set_critical(&ctx->mbox->box,
				"Virtual index's transaction log can't be read after the sync position: %s",
				reason);
		}
		mail_transaction_log_view_close(&log_view);
		return -1;
	}

	i_array_init(&seqs, 8);
	while ((ret = mail_transaction_log_view_next(log_view, &hdr,
						     &data)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0)
			replayed += virtual_sync_replay_rec(ctx, hdr, data,
							    &seqs);
	}
	array_free(&seqs);
	mail_transaction_log_view_close(&log_view);
	if (ret < 0) {
		mailbox_set_index_error(&ctx->mbox->box);
		return -1;
	}
	if (replayed > 0) {
		e_debug(ctx->mbox->box.event,
			"Virtual index has new flag changes - "
			"replayed them on top of the sync");
	}
	return 0;
}

/* Lock the virtual index and commit the sync. Returns 1 if the sync needs to
   be done again, 0 if it was committed, -1 on error. */
static int virtual_sync_commit(struct virtual_sync_context *ctx)
{
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans;
	struct mail_index_sync_rec sync_rec;
	enum mail_index_sync_flags index_sync_flags = ctx->index_sync_flags;
	int ret;

	/* DROP_RECENT is handled by virtual_sync_drop_recent() */
	index_sync_flags &= ENUM_NEGATE(MAIL_INDEX_SYNC_FLAG_DROP_RECENT);
	/* Sync only the changes that virtual_sync_apply_index_changes()
	   already applied to the backend mailboxes. The newer changes are
	   left for the next sync. */
	ret = mail_index_sync_begin_to(ctx->index, &index_sync_ctx, &sync_view,
				       &sync_trans, ctx->log_seq, ctx->log_offset,
				       index_sync_flags);
	if (ret <= 0) {
		mail_index_transaction_rollback(&ctx->trans);
		virtual_sync_reset_state(ctx->mbox);
		if (ret < 0) {
			mailbox_set_index_error(&ctx->mbox->box);
			return -1;
		}
		/* The transaction log was rotated after log_seq/log_offset,
		   or it needs to be rotated. The next round syncs up to the
		   new head. */
		if (ctx->last_try) {
			mail_storage_set_error(ctx->mbox->box.storage,
				MAIL_ERROR_TEMP,
				"Virtual index couldn't be synced up to the already applied log position");
			return -1;
		}
		e_debug(ctx->mbox->box.event,
			"Virtual index can't be synced up to the already applied log position - syncing again");
		return 1;
	}
	/* The sync records still need to be read. Otherwise
	   mail_index_sync_commit() doesn't mark them synced. */
	while (mail_index_sync_next(index_sync_ctx, &sync_rec)) ;

	if (virtual_sync_check_new_changes(ctx, sync_view) < 0 ||
	    virtual_sync_replay_new_flag_changes(ctx) < 0) {
		mail_index_sync_rollback(&index_sync_ctx);
		mail_index_transaction_rollback(&ctx->trans);
		virtual_sync_reset_state(ctx->mbox);
		return -1;
	}

	virtual_sync_index_finish(ctx);
	if ((ctx->index_sync_flags & MAIL_INDEX_SYNC_FLAG_DROP_RECENT) != 0)
		virtual_sync_drop_recent(ctx);

	/* The transaction log is locked by the sync, so this commit doesn't
	   try to lock it again. The changes are mapped by
	   mail_index_sync_commit(). */
	if (mail_index_transaction_commit(&ctx->trans) < 0) {
		mailbox_set_index_error(&ctx->mbox->box);
		mail_index_sync_rollback(&index_sync_ctx);
		virtual_sync_reset_state(ctx->mbox);
		return -1;
	}
	ret = 0;
	if (mail_index_sync_commit(&index_sync_ctx) < 0) {
		mailbox_set_index_error(&ctx->mbox->box);
		ret = -1;
	}
	ctx->mbox->ext_header_rewrite = FALSE;
	return ret;
}

static int virtual_sync_finish(struct virtual_sync_context *ctx, bool success)
{
	struct event *event = ctx->mbox->box.event;
	int ret;

	/* commit the backend mailbox transactions before locking the virtual
	   index */
	virtual_sync_backend_boxes_finish(ctx);
	if (success)
		ret = virtual_sync_commit(ctx);
	else {
		if (ctx->index_broken) {
			/* make sure we don't complain about the same errors
			   over and over again. */
			if (mail_index_unlink(ctx->index) < 0) {
				e_error(event,
					"virtual index %s: Failed to unlink() "
					"broken indexes: %m",
					mailbox_get_path(&ctx->mbox->box));
			}
		}
		mail_index_transaction_rollback(&ctx->trans);
		ret = -1;
	}
	i_assert(ctx->trans == NULL);
	mail_index_view_close(&ctx->view);
	virtual_sync_deinit(&ctx);
	return ret;
}

/* Lock the virtual mailbox for syncing. Only virtual syncs take this lock, so
   its holder never waits for anything that waits for it. This lock isn't
   recursive, but the same virtual mailbox is never synced recursively
   (mail_index_sync_begin() asserts that already). */
static int virtual_sync_lock(struct virtual_mailbox *mbox,
			     struct file_lock **lock_r)
{
	const char *error;

	*lock_r = NULL;
	if (mail_index_is_in_memory(mbox->box.index)) {
		/* Nothing to coordinate with other processes */
		return 0;
	}
	if (mail_index_is_readonly(mbox->box.index)) {
		/* Nothing can be committed to the virtual index, so there's
		   nothing to serialize. The lock file likely couldn't be
		   created either. */
		return 0;
	}
	if (mailbox_lock_file_create(&mbox->box, VIRTUAL_SYNC_LOCK_FNAME,
				     VIRTUAL_SYNC_LOCK_TIMEOUT_SECS,
				     lock_r, &error) <= 0) {
		mailbox_set_critical(&mbox->box,
			"Failed to lock virtual mailbox for syncing: %s", error);
		return -1;
	}
	return 0;
}

static int virtual_sync_run(struct virtual_mailbox *mbox,
			    enum mailbox_sync_flags flags,
			    uint32_t log_seq, uoff_t log_offset, bool last_try)
{
	struct virtual_sync_context *ctx;
	bool broken;
	int ret;

	ctx = i_new(struct virtual_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;
	ctx->index = mbox->box.index;
	ctx->log_seq = log_seq;
	ctx->log_offset = log_offset;
	ctx->last_try = last_try;
	/* Removed messages are expunged when
	   a) EXPUNGE is used
	   b) Mailbox is being opened (FIX_INCONSISTENT is set) */
	ctx->expunge_removed =
		(ctx->flags & (MAILBOX_SYNC_FLAG_EXPUNGE |
			       MAILBOX_SYNC_FLAG_FIX_INCONSISTENT)) != 0;

	ctx->index_sync_flags = MAIL_INDEX_SYNC_FLAG_FLUSH_DIRTY |
		MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES |
		MAIL_INDEX_SYNC_FLAG_STOP_AT_OFFSET;
	if ((mbox->box.flags & MAILBOX_FLAG_DROP_RECENT) != 0)
		ctx->index_sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;

	/* Sync against a private view instead of the view returned by
	   mail_index_sync_begin(), so the virtual index doesn't need to be
	   locked. Internal flag changes are already applied to the index map
	   and internal expunges are only requests, so a refreshed view has the
	   same contents as the sync's view. The view may already have changes
	   after log_seq/log_offset, but they can only be flag and keyword
	   changes and expunge requests. They're left for the next sync. */
	if (mail_index_refresh(ctx->index) < 0) {
		mailbox_set_index_error(&mbox->box);
		virtual_sync_deinit(&ctx);
		return -1;
	}
	ctx->view = mail_index_view_open(ctx->index);
	ctx->trans = mail_index_transaction_begin(ctx->view,
		MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL |
		MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES);

	ret = virtual_mailbox_ext_header_read(mbox, ctx->view, &broken);
	if (ret < 0)
		return virtual_sync_finish(ctx, FALSE);
	if (broken)
		ctx->index_broken = TRUE;
	/* update list of UIDs in backend mailboxes */
	if (virtual_sync_backend_boxes(ctx) < 0)
		return virtual_sync_finish(ctx, FALSE);
	return virtual_sync_finish(ctx, TRUE);
}

static int virtual_sync(struct virtual_mailbox *mbox,
			enum mailbox_sync_flags flags)
{
	struct file_lock *lock;
	uint32_t log_seq;
	uoff_t log_offset;
	unsigned int i;
	int ret;

	if (virtual_sync_lock(mbox, &lock) < 0)
		return -1;
	virtual_sync_backend_boxes_set_no_autocreate(mbox, TRUE);
	for (i = 0;; i++) {
		ret = virtual_sync_apply_index_changes(mbox, &log_seq,
						       &log_offset);
		if (ret < 0)
			break;
		ret = virtual_sync_run(mbox, flags, log_seq, log_offset,
				       i == VIRTUAL_SYNC_MAX_RETRIES);
		if (ret <= 0)
			break;
	}
	virtual_sync_backend_boxes_set_no_autocreate(mbox, FALSE);
	file_lock_free(&lock);
	return ret;
}

struct mailbox_sync_context *
virtual_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct virtual_mailbox *mbox =
		container_of(box, struct virtual_mailbox, box);
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
