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
#include <stdlib.h>

static void mail_index_transaction_add_last(struct mail_index_transaction *t);

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     int hide, int external)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->view = view;
	t->hide_transaction = hide;
	t->external = external;
	t->first_new_seq = mail_index_view_get_messages_count(t->view)+1;

	if (view->syncing) {
		/* transaction view cannot work if new records are being added
		   in two places. make sure it doesn't happen. */
		t->no_appends = TRUE;
	}

	return t;
}

static void mail_keyword_transaction_free(struct mail_keyword_transaction *kt)
{
	struct mail_keyword_transaction **p;

	for (p = &kt->keywords->kt; *p != NULL; p = &(*p)->next) {
		if (*p == kt) {
			*p = kt->next;
			break;
		}
	}

	if (*p == NULL) {
		/* no transactions left, free mail_keywords */
		i_assert(kt->keywords->kt == NULL);
		i_free(kt->keywords);
	}

	if (kt->messages != NULL)
		buffer_free(kt->messages);
	i_free(kt);
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

	if (t->keyword_updates != NULL) {
		struct mail_keyword_transaction **kt;

		kt = buffer_get_modifyable_data(t->keyword_updates, &size);
		size /= sizeof(*kt);

		for (i = 0; i < size; i++)
			mail_keyword_transaction_free(kt[i]);
		buffer_free(t->keyword_updates);
	}

	if (t->appends != NULL)
		buffer_free(t->appends);
	if (t->expunges != NULL)
		buffer_free(t->expunges);
	if (t->updates != NULL)
		buffer_free(t->updates);
	if (t->ext_resizes != NULL)
		buffer_free(t->ext_resizes);
	if (t->ext_resets != NULL)
		buffer_free(t->ext_resets);
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

	if (t->keyword_updates != NULL) {
		struct mail_keyword_transaction **kt;

		kt = buffer_get_modifyable_data(t->keyword_updates, &size);
		size /= sizeof(*kt);

		for (i = 0; i < size; i++) {
			if (kt[i]->messages == NULL)
				continue;

			mail_index_buffer_convert_to_uids(t, kt[i]->messages,
				sizeof(uint32_t) * 2, TRUE);
		}
	}

	mail_index_buffer_convert_to_uids(t, t->expunges,
		sizeof(struct mail_transaction_expunge), TRUE);
	mail_index_buffer_convert_to_uids(t, t->updates,
		sizeof(struct mail_transaction_flag_update), TRUE);
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

	i_assert(!t->no_appends);

	t->log_updates = TRUE;

	if (t->appends == NULL)
		t->appends = buffer_create_dynamic(default_pool, 4096);

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

struct seq_range {
	uint32_t seq1, seq2;
};

static void mail_index_update_seq_range_buffer(buffer_t *buffer, uint32_t seq)
{
        struct seq_range *data, value;
	unsigned int idx, left_idx, right_idx;
	size_t size;

	value.seq1 = value.seq2 = seq;

	data = buffer_get_modifyable_data(buffer, &size);
	size /= sizeof(*data);
	i_assert(size > 0);

	/* quick checks */
	if (data[size-1].seq2 == seq-1) {
		/* grow last range */
		data[size-1].seq2 = seq;
		return;
	}
	if (data[size-1].seq2 < seq) {
		buffer_append(buffer, &value, sizeof(value));
		return;
	}
	if (data[0].seq1 == seq+1) {
		/* grow down first range */
		data[0].seq1 = seq;
		return;
	}
	if (data[0].seq1 > seq) {
		buffer_insert(buffer, 0, &value, sizeof(value));
		return;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	idx = 0; left_idx = 0; right_idx = size;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].seq1 <= seq) {
			if (data[idx].seq2 >= seq) {
				/* it's already expunged */
				return;
			}
			left_idx = idx+1;
		} else {
			right_idx = idx;
		}
	}

	if (data[idx].seq2 < seq)
		idx++;

        /* idx == size couldn't happen because we already handle it above */
	i_assert(idx < size && data[idx].seq1 >= seq);
	i_assert(data[idx].seq1 > seq || data[idx].seq2 < seq);

	if (data[idx].seq1 == seq+1) {
		data[idx].seq1 = seq;
		if (idx > 0 && data[idx-1].seq2 == seq-1) {
			/* merge */
			data[idx-1].seq2 = data[idx].seq2;
			buffer_delete(buffer, idx * sizeof(*data),
				      sizeof(*data));
		}
	} else if (data[idx].seq2 == seq-1) {
		i_assert(idx+1 < size); /* already handled above */
		data[idx].seq2 = seq;
		if (data[idx+1].seq1 == seq+1) {
			/* merge */
			data[idx+1].seq1 = data[idx].seq1;
			buffer_delete(buffer, idx * sizeof(*data),
				      sizeof(*data));
		}
	} else {
		buffer_insert(buffer, idx * sizeof(*data),
                              &value, sizeof(value));
	}
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(t->view));

	t->log_updates = TRUE;

	/* expunges is a sorted array of {seq1, seq2, ..}, .. */
	if (t->expunges == NULL) {
		t->expunges = buffer_create_dynamic(default_pool, 1024);
		buffer_append(t->expunges, &seq, sizeof(seq));
		buffer_append(t->expunges, &seq, sizeof(seq));
		return;
	}

	mail_index_update_seq_range_buffer(t->expunges, seq);
}

static void mail_index_record_modify_flags(struct mail_index_record *rec,
					   enum modify_type modify_type,
					   enum mail_flags flags)
{
	switch (modify_type) {
	case MODIFY_REPLACE:
		rec->flags = flags;
		break;
	case MODIFY_ADD:
		rec->flags |= flags;
		break;
	case MODIFY_REMOVE:
		rec->flags &= ~flags;
		break;
	}
}

#define IS_COMPATIBLE_UPDATE(t, modify_type, flags) \
	((t)->last_update_modify_type == (modify_type) && \
	 (t)->last_update.add_flags == (flags))

void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags)
{
	struct mail_index_record *rec;

	t->log_updates = TRUE;

	if (seq >= t->first_new_seq) {
		/* just appended message, modify it directly */
                rec = mail_index_transaction_lookup(t, seq);
		mail_index_record_modify_flags(rec, modify_type, flags);
		return;
	}

	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(t->view));

	/* first get group updates into same structure. this allows faster
	   updates if same mails have multiple flag updates during same
	   transaction (eg. 1:10 +seen, 1:10 +deleted) */
	if (t->last_update.uid2 == seq-1) {
		if (t->last_update.uid1 != 0 &&
		    IS_COMPATIBLE_UPDATE(t, modify_type, flags)) {
			t->last_update.uid2 = seq;
			return;
		}
	} else if (t->last_update.uid1 == seq+1) {
		if (t->last_update.uid1 != 0 &&
		    IS_COMPATIBLE_UPDATE(t, modify_type, flags)) {
			t->last_update.uid1 = seq;
			return;
		}
	}

	if (t->last_update.uid1 != 0)
		mail_index_transaction_add_last(t);

	t->last_update_modify_type = modify_type;
	t->last_update.uid1 = t->last_update.uid2 = seq;
	t->last_update.add_flags = flags;
}

static void
mail_index_transaction_get_last(struct mail_index_transaction *t,
				struct mail_transaction_flag_update *update)
{
	*update = t->last_update;
	switch (t->last_update_modify_type) {
	case MODIFY_REPLACE:
		/* remove_flags = ~add_flags */
		update->remove_flags =
			~update->add_flags & MAIL_INDEX_FLAGS_MASK;
		break;
	case MODIFY_ADD:
		/* already in add_flags */
		break;
	case MODIFY_REMOVE:
		/* add_flags -> remove_flags */
		update->remove_flags = update->add_flags;
		update->add_flags = 0;
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

	if (t->updates == NULL)
		t->updates = buffer_create_dynamic(default_pool, 4096);

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
		*buffer = buffer_create_dynamic(default_pool, 1024);
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

void mail_index_ext_resize(struct mail_index_transaction *t, uint32_t ext_id,
			   uint32_t hdr_size, uint16_t record_size,
			   uint16_t record_align)
{
	struct mail_transaction_ext_intro intro;
	const struct mail_index_ext *ext;

	memset(&intro, 0, sizeof(intro));

	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &intro.ext_id)) {
		intro.ext_id = (uint32_t)-1;
		ext = t->view->index->extensions->data;
		ext += ext_id;
	} else {
		ext = t->view->map->extensions->data;
		ext += ext_id;
	}

	/* allow only header size changes if something was already written */
	i_assert(t->ext_rec_updates == NULL ||
		 (ext->record_size == record_size &&
		  ext->record_align == record_align));

	t->log_updates = TRUE;

	if (t->ext_resizes == NULL)
		t->ext_resizes = buffer_create_dynamic(default_pool, 128);

	intro.hdr_size = hdr_size;
	intro.record_size = record_size;
	intro.record_align = record_align;
	intro.name_size = 1;
	buffer_write(t->ext_resizes, ext_id * sizeof(intro),
		     &intro, sizeof(intro));
}

void mail_index_ext_reset(struct mail_index_transaction *t, uint32_t ext_id,
			  uint32_t reset_id)
{
	size_t pos;

	i_assert(reset_id != 0);

	t->log_updates = TRUE;

	if (t->ext_rec_updates != NULL &&
	    ext_id < t->ext_rec_updates->used / sizeof(buffer_t *)) {
		buffer_t *const *buf = t->ext_rec_updates->data;
		buf += ext_id;

		if (*buf != NULL) 
			buffer_set_used_size(*buf, 0);
	}

	pos = ext_id * sizeof(uint32_t);
	if (t->ext_resets == NULL) {
		t->ext_resets = buffer_create_dynamic(default_pool,
						      pos + sizeof(uint32_t));
	}
	buffer_write(t->ext_resets, pos, &reset_id, sizeof(reset_id));
}

void mail_index_update_header_ext(struct mail_index_transaction *t,
				  uint32_t ext_id, size_t offset,
				  const void *data, size_t size)
{
	// FIXME
}

void mail_index_update_ext(struct mail_index_transaction *t, uint32_t seq,
			   uint32_t ext_id, const void *data, void *old_data_r)
{
	struct mail_index *index = t->view->index;
        const struct mail_index_ext *ext;
	const struct mail_transaction_ext_intro *intro;
	buffer_t **buf;
	uint16_t record_size;
	size_t size;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(ext_id < index->extensions->used / sizeof(*ext));

	t->log_updates = TRUE;

	if (t->ext_resizes == NULL) {
		intro = NULL;
		size = 0;
	} else {
		intro = buffer_get_data(t->ext_resizes, &size);
	}
	if (ext_id < size / sizeof(*intro) && intro[ext_id].name_size != 0) {
		/* resized record */
		record_size = intro[ext_id].record_size;
	} else {
		ext = index->extensions->data;
		record_size = ext[ext_id].record_size;
	}

	if (t->ext_rec_updates == NULL)
		t->ext_rec_updates = buffer_create_dynamic(default_pool, 128);
	buf = buffer_get_space_unsafe(t->ext_rec_updates,
				      ext_id * sizeof(buffer_t *),
				      sizeof(buffer_t *));

	/* @UNSAFE */
	if (!mail_index_update_seq_buffer(buf, seq, data, record_size,
					  old_data_r)) {
		if (old_data_r != NULL)
			memset(old_data_r, 0, record_size);
	}
}

static struct mail_keyword_transaction *
mail_keyword_transaction_new(struct mail_index_transaction *t,
			     struct mail_keywords *keywords)
{
	struct mail_keyword_transaction *kt;

	if (t->keyword_updates == NULL)
                t->keyword_updates = buffer_create_dynamic(default_pool, 512);

	kt = i_new(struct mail_keyword_transaction, 1);
	kt->transaction = t;
	kt->keywords = keywords;

	kt->next = keywords->kt;
	keywords->kt = kt;

	buffer_append(t->keyword_updates, &kt, sizeof(kt));
	return kt;
}

static struct mail_keywords *
mail_index_keywords_build(struct mail_index *index,
			  const char *const keywords[], unsigned int count)
{
	struct mail_keywords k;
	const char **missing_keywords, *keyword;
	buffer_t *keyword_buf;
	unsigned int i, j, bitmask_offset, missing_count = 0;
	size_t size;
	uint8_t *b;

	if (count == 0)
		return i_new(struct mail_keywords, 1);

	/* @UNSAFE */
	t_push();

	missing_keywords = t_new(const char *, count + 1);
	memset(&k, 0, sizeof(k));

	/* keywords are sorted in index. look up the existing ones and add
	   new ones. build a bitmap pointing to them. keywords are never
	   removed from index's keyword list. */
	bitmask_offset = sizeof(k) - sizeof(k.bitmask);
	keyword_buf = buffer_create_dynamic(default_pool, bitmask_offset +
					    (count + 7) / 8 + 8);
	for (i = 0; i < count; i++) {
		for (j = 0; index->keywords[j] != NULL; j++) {
			if (strcasecmp(keywords[i], index->keywords[j]) == 0)
				break;
		}

		if (index->keywords[j] != NULL) {
			if (keyword_buf->used == 0) {
				/* first one */
				k.start = j;
			} else if (j < k.start) {
				buffer_copy(keyword_buf,
					    bitmask_offset + k.start - j,
					    keyword_buf, bitmask_offset,
					    (size_t)-1);
				k.start = j;
			}
			b = buffer_get_space_unsafe(keyword_buf,
						    bitmask_offset +
						    (j - k.start) / 8, 1);
			*b |= 1 << ((j - k.start) % 8);
			k.end = j;
			k.count++;
		} else {
			/* arrays are sorted, can't match anymore */
			missing_keywords[missing_count++] = keywords[i];
		}
	}

	if (missing_count > 0) {
		/* add missing keywords. first drop the trailing NULL. */
		size = index->keywords_buf->used - sizeof(const char *);
		buffer_set_used_size(index->keywords_buf, size);

		j = size / sizeof(const char *);
		for (; *missing_keywords != NULL; missing_keywords++, j++) {
			keyword = p_strdup(index->keywords_pool,
					   *missing_keywords);
			buffer_append(index->keywords_buf,
				      &keyword, sizeof(keyword));

			b = buffer_get_space_unsafe(keyword_buf,
						    bitmask_offset +
						    (j - k.start) / 8, 1);
			*b |= 1 << ((j - k.start) % 8);
			k.end = j;
			k.count++;
		}

		buffer_append_zero(index->keywords_buf, sizeof(const char *));
		index->keywords = index->keywords_buf->data;
	}
	buffer_write(keyword_buf, 0, &k, bitmask_offset);

	t_pop();
	return buffer_free_without_data(keyword_buf);
}

struct mail_keywords *
mail_index_keywords_create(struct mail_index_transaction *t,
			   const char *const keywords[])
{
	struct mail_keywords *k;
	const char *const null_keywords[] = { NULL };

	if (keywords == NULL)
		keywords = null_keywords;

	k = mail_index_keywords_build(t->view->index, keywords,
				      strarray_length(keywords));
	(void)mail_keyword_transaction_new(t, k);
	return k;
}

void mail_index_update_keywords(struct mail_index_transaction *t, uint32_t seq,
				enum modify_type modify_type,
				struct mail_keywords *keywords)
{
	struct mail_keyword_transaction *kt;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(keywords->count > 0 || modify_type == MODIFY_REPLACE);

	for (kt = keywords->kt; kt != NULL; kt = kt->next) {
		if (kt->transaction == t &&
		    (kt->modify_type == modify_type || kt->messages == NULL))
			break;
	}

	if (kt == NULL)
		kt = mail_keyword_transaction_new(t, keywords);

	if (kt->messages == NULL) {
		kt->messages = buffer_create_dynamic(default_pool, 32);
		kt->modify_type = modify_type;
		buffer_append(kt->messages, &seq, sizeof(seq));
		buffer_append(kt->messages, &seq, sizeof(seq));
	} else {
		mail_index_update_seq_range_buffer(kt->messages, seq);
	}
	t->log_updates = TRUE;
}
