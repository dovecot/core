/* Copyright (C) 2003-2004 Timo Sirainen */

/* Inside transaction we keep messages stored in sequences in uid fields.
   Before they're written to transaction log the sequences are changed to
   UIDs. This is because we're able to compress sequence ranges better. */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>

static void mail_index_transaction_add_last(struct mail_index_transaction *t);

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view, int hide)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->view = view;
	t->hide_transaction = hide;
	t->first_new_seq = mail_index_view_get_message_count(t->view)+1;
	return t;
}

static void mail_index_transaction_free(struct mail_index_transaction *t)
{
	buffer_t **recs;
	size_t i, size;

	mail_index_view_transaction_unref(t->view);

	if (t->ext_rec_updates != NULL) {
		recs = buffer_get_modifyable_data(t->ext_rec_updates, &size);
		size /= sizeof(*recs);

		for (i = 0; i < size; i++) {
			if (recs[i] != NULL)
				buffer_free(recs[i]);
		}
		buffer_free(t->ext_rec_updates);
	}

	if (t->appends != NULL)
		buffer_free(t->appends);
	if (t->expunges != NULL)
		buffer_free(t->expunges);
	if (t->updates != NULL)
		buffer_free(t->updates);
	if (t->cache_updates != NULL)
		buffer_free(t->cache_updates);
	if (t->ext_intros != NULL)
		buffer_free(t->ext_intros);
	i_free(t);
}

void mail_index_transaction_ref(struct mail_index_transaction *t)
{
	t->refcount++;
}

void mail_index_transaction_unref(struct mail_index_transaction *t)
{
	if (--t->refcount == 0)
		mail_index_transaction_free(t);
}

static void
mail_index_buffer_convert_to_uids(struct mail_index_transaction *t,
				  buffer_t *buf, size_t record_size, int range)
{
        struct mail_index_view *view = t->view;
	const struct mail_index_record *rec;
	unsigned char *data;
	size_t size, i;
	uint32_t *seq;
	int j;

	if (buf == NULL)
		return;

	/* @UNSAFE */
	data = buffer_get_modifyable_data(buf, &size);
	for (i = 0; i < size; i += record_size) {
		seq = (uint32_t *)&data[i];

		for (j = 0; j <= range; j++, seq++) {
			if (*seq >= t->first_new_seq) {
				rec = mail_index_transaction_lookup(t, *seq);
				*seq = rec->uid;
			} else {
				i_assert(*seq <= view->map->records_count);
				*seq = MAIL_INDEX_MAP_IDX(view->map,
							  *seq - 1)->uid;
			}
			i_assert(*seq != 0);
		}
	}
}

static int
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	struct mail_index *index = t->view->index;
        const struct mail_index_ext *extensions;
	buffer_t **updates;
	size_t i, size;

	if (mail_index_view_lock(t->view) < 0)
		return -1;

	if (t->ext_rec_updates != NULL) {
		extensions = buffer_get_data(index->extensions, NULL);
		updates = buffer_get_modifyable_data(t->ext_rec_updates, &size);
		size /= sizeof(*updates);

		for (i = 0; i < size; i++) {
			if (updates[i] == NULL)
				continue;

			mail_index_buffer_convert_to_uids(t, updates[i],
				sizeof(uint32_t) + extensions[i].record_size,
				FALSE);
		}
	}

	mail_index_buffer_convert_to_uids(t, t->expunges,
		sizeof(struct mail_transaction_expunge), TRUE);
	mail_index_buffer_convert_to_uids(t, t->updates,
		sizeof(struct mail_transaction_flag_update), TRUE);
	mail_index_buffer_convert_to_uids(t, t->cache_updates,
		sizeof(struct mail_transaction_cache_update), FALSE);
	return 0;
}

int mail_index_transaction_commit(struct mail_index_transaction *t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r)
{
	int ret;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_transaction_rollback(t);
		return -1;
	}

	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_commit(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}

	if (t->last_update.uid1 != 0)
		mail_index_transaction_add_last(t);

	if (mail_index_transaction_convert_to_uids(t) < 0)
		ret = -1;
	else {
		ret = mail_transaction_log_append(t, log_file_seq_r,
						  log_file_offset_r);
	}

	mail_index_transaction_unref(t);
	return ret;
}

void mail_index_transaction_rollback(struct mail_index_transaction *t)
{
	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_rollback(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}
        mail_index_transaction_unref(t);
}

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq)
{
	size_t pos;

	i_assert(seq >= t->first_new_seq && seq <= t->last_new_seq);

	pos = (seq - t->first_new_seq) * sizeof(struct mail_index_record);
	return buffer_get_space_unsafe(t->appends, pos,
				       sizeof(struct mail_index_record));
}

void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r)
{
        struct mail_index_record *rec;

	t->log_updates = TRUE;

	if (t->appends == NULL) {
		t->appends = buffer_create_dynamic(default_pool,
						   4096, (size_t)-1);
	}

	/* sequence number is visible only inside given view,
	   so let it generate it */
	if (t->last_new_seq != 0)
		*seq_r = ++t->last_new_seq;
	else
		*seq_r = t->last_new_seq = t->first_new_seq;

	rec = buffer_append_space_unsafe(t->appends, sizeof(*rec));
	memset(rec, 0, sizeof(*rec));
	rec->uid = uid;
}

void mail_index_append_assign_uids(struct mail_index_transaction *t,
				   uint32_t first_uid, uint32_t *next_uid_r)
{
        struct mail_index_record *rec, *end;
	size_t size;

	if (t->appends == NULL)
		return;

	rec = buffer_get_modifyable_data(t->appends, &size);
	end = PTR_OFFSET(rec, size);

	/* find the first mail with uid = 0 */
	for (; rec != end; rec++) {
		if (rec->uid == 0)
			break;
	}

	for (; rec != end; rec++) {
		i_assert(rec->uid == 0);
		rec->uid = first_uid++;
	}

	*next_uid_r = first_uid;
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
        struct mail_transaction_expunge exp, *data;
	unsigned int idx, left_idx, right_idx;
	size_t size;

	i_assert(seq > 0 && seq <= mail_index_view_get_message_count(t->view));

	t->log_updates = TRUE;
	exp.uid1 = exp.uid2 = seq;

	/* expunges is a sorted array of {seq1, seq2, ..}, .. */

	if (t->expunges == NULL) {
		t->expunges = buffer_create_dynamic(default_pool,
						    1024, (size_t)-1);
		buffer_append(t->expunges, &exp, sizeof(exp));
		return;
	}

	data = buffer_get_modifyable_data(t->expunges, &size);
	size /= sizeof(*data);
	i_assert(size > 0);

	/* quick checks */
	if (data[size-1].uid2 == seq-1) {
		/* grow last range */
		data[size-1].uid2 = seq;
		return;
	}
	if (data[size-1].uid2 < seq) {
		buffer_append(t->expunges, &exp, sizeof(exp));
		return;
	}
	if (data[0].uid1 == seq+1) {
		/* grow down first range */
		data[0].uid1 = seq;
		return;
	}
	if (data[0].uid1 > seq) {
		buffer_insert(t->expunges, 0, &exp, sizeof(exp));
		return;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	idx = 0; left_idx = 0; right_idx = size;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].uid1 <= seq) {
			if (data[idx].uid2 >= seq) {
				/* it's already expunged */
				return;
			}
			left_idx = idx+1;
		} else {
			right_idx = idx;
		}
	}

	if (data[idx].uid2 < seq)
		idx++;

        /* idx == size couldn't happen because we already handle it above */
	i_assert(idx < size && data[idx].uid1 >= seq);
	i_assert(data[idx].uid1 > seq || data[idx].uid2 < seq);

	if (data[idx].uid1 == seq+1) {
		data[idx].uid1 = seq;
		if (idx > 0 && data[idx-1].uid2 == seq-1) {
			/* merge */
			data[idx-1].uid2 = data[idx].uid2;
			buffer_delete(t->expunges, idx * sizeof(*data),
				      sizeof(*data));
		}
	} else if (data[idx].uid2 == seq-1) {
		i_assert(idx+1 < size); /* already handled above */
		data[idx].uid2 = seq;
		if (data[idx+1].uid1 == seq+1) {
			/* merge */
			data[idx+1].uid1 = data[idx].uid1;
			buffer_delete(t->expunges, idx * sizeof(*data),
				      sizeof(*data));
		}
	} else {
		buffer_insert(t->expunges, idx * sizeof(*data),
                              &exp, sizeof(exp));
	}
}

static void mail_index_record_modify_flags(struct mail_index_record *rec,
					   enum modify_type modify_type,
					   enum mail_flags flags,
					   keywords_mask_t keywords)
{
	int i;

	switch (modify_type) {
	case MODIFY_REPLACE:
		rec->flags = flags;
		memcpy(rec->keywords, keywords, INDEX_KEYWORDS_BYTE_COUNT);
		break;
	case MODIFY_ADD:
		rec->flags |= flags;
		for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++)
			rec->keywords[i] |= keywords[i];
		break;
	case MODIFY_REMOVE:
		rec->flags &= ~flags;
		for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++)
			rec->keywords[i] &= ~keywords[i];
		break;
	}
}

#define IS_COMPATIBLE_UPDATE(t, modify_type, flags, keywords) \
	((t)->last_update_modify_type == (modify_type) && \
	 (t)->last_update.add_flags == (flags) && \
	 memcmp((t)->last_update.add_keywords, keywords, \
	        INDEX_KEYWORDS_BYTE_COUNT) == 0)

void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags, keywords_mask_t keywords)
{
	struct mail_index_record *rec;

	t->log_updates = TRUE;

	if (seq >= t->first_new_seq) {
		/* just appended message, modify it directly */
                rec = mail_index_transaction_lookup(t, seq);
		mail_index_record_modify_flags(rec, modify_type,
					       flags, keywords);
		return;
	}

	i_assert(seq > 0 && seq <= mail_index_view_get_message_count(t->view));

	/* first get group updates into same structure. this allows faster
	   updates if same mails have multiple flag updates during same
	   transaction (eg. 1:10 +seen, 1:10 +deleted) */
	if (t->last_update.uid2 == seq-1) {
		if (t->last_update.uid1 != 0 &&
		    IS_COMPATIBLE_UPDATE(t, modify_type, flags, keywords)) {
			t->last_update.uid2 = seq;
			return;
		}
	} else if (t->last_update.uid1 == seq+1) {
		if (t->last_update.uid1 != 0 &&
		    IS_COMPATIBLE_UPDATE(t, modify_type, flags, keywords)) {
			t->last_update.uid1 = seq;
			return;
		}
	}

	if (t->last_update.uid1 != 0)
		mail_index_transaction_add_last(t);

	t->last_update_modify_type = modify_type;
	t->last_update.uid1 = t->last_update.uid2 = seq;
	t->last_update.add_flags = flags;
	memcpy(t->last_update.add_keywords, keywords,
	       INDEX_KEYWORDS_BYTE_COUNT);
}

static void
mail_index_transaction_get_last(struct mail_index_transaction *t,
				struct mail_transaction_flag_update *update)
{
	int i;

	*update = t->last_update;
	switch (t->last_update_modify_type) {
	case MODIFY_REPLACE:
		/* remove_flags = ~add_flags */
		update->remove_flags =
			~update->add_flags & MAIL_INDEX_FLAGS_MASK;
		for (i = 0; i < INDEX_KEYWORDS_BYTE_COUNT; i++)
			update->remove_keywords[i] = ~update->add_keywords[i];
		break;
	case MODIFY_ADD:
		/* already in add_flags */
		break;
	case MODIFY_REMOVE:
		/* add_flags -> remove_flags */
		update->remove_flags = update->add_flags;
		memcpy(&update->remove_keywords, &update->add_keywords,
		       INDEX_KEYWORDS_BYTE_COUNT);
		update->add_flags = 0;
		memset(&update->add_keywords, 0, INDEX_KEYWORDS_BYTE_COUNT);
		break;
	}
}

static void mail_index_transaction_add_last(struct mail_index_transaction *t)
{
	struct mail_transaction_flag_update update, *data;
	unsigned int idx, left_idx, right_idx;
	uint32_t last;
	size_t size;

        mail_index_transaction_get_last(t, &update);

	if (t->updates == NULL) {
		t->updates = buffer_create_dynamic(default_pool,
						   4096, (size_t)-1);
	}

	data = buffer_get_modifyable_data(t->updates, &size);
	size /= sizeof(*data);

	/* find the nearest sequence from existing updates */
	idx = 0; left_idx = 0; right_idx = size;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].uid1 < update.uid1)
			left_idx = idx+1;
		else if (data[idx].uid1 > update.uid1)
			right_idx = idx;
		else
			break;
	}
	if (idx < size && data[idx].uid2 < update.uid1)
		idx++;

	i_assert(idx == size || data[idx].uid1 <= update.uid1);

	/* insert it into buffer, split it in multiple parts if needed
	   to make sure the ordering stays the same */
	for (; idx < size; idx++) {
		if (data[idx].uid1 > update.uid2)
			break;

		/* partial */
		last = update.uid2;
		update.uid2 = data[idx].uid1-1;

		if (update.uid1 <= update.uid2) {
			buffer_insert(t->updates, idx * sizeof(update),
				      &update, sizeof(update));
			data = buffer_get_modifyable_data(t->updates, NULL);
			size++;
		}

		update.uid1 = update.uid2+1;
		update.uid2 = last;
	}

	buffer_insert(t->updates, idx * sizeof(update),
		      &update, sizeof(update));
}

int mail_index_seq_buffer_lookup(buffer_t *buffer, uint32_t seq,
				 size_t record_size, size_t *pos_r)
{
	unsigned int idx, left_idx, right_idx;
	void *data;
	uint32_t full_record_size, *seq_p;
	size_t size;

	full_record_size = record_size + sizeof(seq);

	data = buffer_get_modifyable_data(buffer, &size);

	/* we're probably appending it, check */
	if (size == 0)
		idx = 0;
	else if (*((uint32_t *)PTR_OFFSET(data, size-full_record_size)) < seq)
		idx = size / full_record_size;
	else {
		idx = 0; left_idx = 0; right_idx = size / full_record_size;
		while (left_idx < right_idx) {
			idx = (left_idx + right_idx) / 2;

			seq_p = PTR_OFFSET(data, idx * full_record_size);
			if (*seq_p < seq)
				left_idx = idx+1;
			else if (*seq_p > seq)
				right_idx = idx;
			else {
				*pos_r = idx * full_record_size;
				return TRUE;
			}
		}
	}

	*pos_r = idx * full_record_size;
	return FALSE;
}

static int mail_index_update_seq_buffer(buffer_t **buffer, uint32_t seq,
					const void *record, size_t record_size,
					void *old_record)
{
	void *p;
	size_t pos;

	if (*buffer == NULL) {
		*buffer = buffer_create_dynamic(default_pool, 1024, (size_t)-1);
		buffer_append(*buffer, &seq, sizeof(seq));
		buffer_append(*buffer, record, record_size);
		return FALSE;
	}

	if (mail_index_seq_buffer_lookup(*buffer, seq, record_size, &pos)) {
		/* already there, update */
		p = buffer_get_space_unsafe(*buffer, pos + sizeof(seq),
					    record_size);
		if (old_record != NULL)
			memcpy(old_record, p, record_size);
		memcpy(p, record, record_size);
		return TRUE;
	} else {
		/* insert */
		buffer_copy(*buffer, pos + sizeof(seq) + record_size,
			    *buffer, pos, (size_t)-1);
		buffer_write(*buffer, pos, &seq, sizeof(seq));
		buffer_write(*buffer, pos + sizeof(seq), record, record_size);
		return FALSE;
	}
}

static void
mail_index_transaction_reset_cache_updates(struct mail_index_transaction *t)
{
	struct mail_index_record *rec;
	uint32_t seq;

	if (t->last_cache_file_seq == 0)
		return;

	buffer_set_used_size(t->cache_updates, 0);

	if (t->first_new_seq != 0) {
		for (seq = t->first_new_seq; seq <= t->last_new_seq; seq++) {
			rec = mail_index_transaction_lookup(t, seq);
			rec->cache_offset = 0;
		}
	}
}

void mail_index_reset_cache(struct mail_index_transaction *t,
			    uint32_t new_file_seq)
{
	t->log_updates = TRUE;

	mail_index_transaction_reset_cache_updates(t);
	t->new_cache_file_seq = new_file_seq;
        t->last_cache_file_seq = new_file_seq;
}

void mail_index_update_cache(struct mail_index_transaction *t, uint32_t seq,
			     uint32_t file_seq, uint32_t offset,
			     uint32_t *old_offset_r)
{
	struct mail_index_record *rec;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_message_count(t->view) ||
		  seq <= t->last_new_seq));

	t->log_updates = TRUE;

	if (file_seq != t->last_cache_file_seq) {
		mail_index_transaction_reset_cache_updates(t);
                t->last_cache_file_seq = file_seq;
	}

	if (seq >= t->first_new_seq) {
		/* just appended message, modify it directly */
		rec = mail_index_transaction_lookup(t, seq);
		*old_offset_r = rec->cache_offset;
		rec->cache_offset = offset;
	} else {
		if (!mail_index_update_seq_buffer(&t->cache_updates, seq,
						  &offset, sizeof(offset),
						  old_offset_r))
			*old_offset_r = 0;
	}
}

int mail_index_update_cache_lookup(struct mail_index_transaction *t,
				   uint32_t seq, uint32_t *offset_r)
{
	const void *p;
	size_t pos;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_message_count(t->view) ||
		  seq <= t->last_new_seq));

	if (t->cache_updates == NULL)
		return FALSE;

	if (MAIL_CACHE_IS_UNUSABLE(t->view->index->cache) ||
	    t->view->index->cache->hdr->file_seq != t->last_cache_file_seq) {
		/* cache file was recreated, our offsets don't work anymore */
		mail_index_transaction_reset_cache_updates(t);
		t->last_cache_file_seq = 0;
		return FALSE;
	}

	if (!mail_index_seq_buffer_lookup(t->cache_updates, seq,
					  sizeof(*offset_r), &pos))
		return FALSE;

	p = buffer_get_data(t->cache_updates, NULL);
	memcpy(offset_r, CONST_PTR_OFFSET(p, pos + sizeof(*offset_r)),
	       sizeof(*offset_r));
	return TRUE;
}

void mail_index_update_ext(struct mail_index_transaction *t,
			   uint32_t seq, uint32_t ext_id, const void *data)
{
	struct mail_index *index = t->view->index;
        const struct mail_index_ext *ext;
	buffer_t **buf;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_message_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(ext_id < index->extensions->used / sizeof(*ext));

	t->log_updates = TRUE;

	ext = index->extensions->data;
	ext += ext_id;

	if (t->ext_rec_updates == NULL) {
		t->ext_rec_updates =
			buffer_create_dynamic(default_pool, 128, (size_t)-1);
	}
	buf = buffer_get_space_unsafe(t->ext_rec_updates,
				      ext_id * sizeof(buffer_t *),
				      sizeof(buffer_t *));
	mail_index_update_seq_buffer(buf, seq, data, ext->record_size, NULL);
}

void mail_index_update_header(struct mail_index_transaction *t,
			      size_t offset, const void *data, size_t size)
{
	i_assert(offset < sizeof(t->hdr_change));
	i_assert(size <= sizeof(t->hdr_change) - offset);

	t->hdr_changed = TRUE;
	t->log_updates = TRUE;

	memcpy(t->hdr_change + offset, data, size);
	for (; size > 0; size--)
		t->hdr_mask[offset++] = 1;
}
