/* Copyright (C) 2003-2004 Timo Sirainen */

/* Inside transaction we keep messages stored in sequences in uid fields.
   Before they're written to transaction log the sequences are changed to
   UIDs. This is because we're able to compress sequence ranges better. */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"
#include "mail-index-transaction-private.h"

static void mail_index_transaction_add_last(struct mail_index_transaction *t);

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view, int hide)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->view = view;
	t->hide_transaction = hide;
	return t;
}

static void mail_index_transaction_free(struct mail_index_transaction *t)
{
	mail_index_view_transaction_unref(t->view);
	if (t->appends != NULL)
		buffer_free(t->appends);
	if (t->expunges != NULL)
		buffer_free(t->expunges);
	if (t->updates != NULL)
		buffer_free(t->updates);
	i_free(t);
}

static void
mail_index_buffer_convert_to_uids(struct mail_index_view *view,
				  buffer_t *buf, size_t record_size, int range)
{
	unsigned char *data;
	size_t size, i;
	uint32_t *seq;

	if (buf == NULL)
		return;

	/* @UNSAFE */
	data = buffer_get_modifyable_data(buf, &size);
	for (i = 0; i < size; i += record_size) {
		seq = (uint32_t *)&data[i];

		seq[0] = view->map->records[seq[0]-1].uid;
		if (range)
			seq[1] = view->map->records[seq[1]-1].uid;
	}
}

static int
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	if (mail_index_view_lock(t->view) < 0)
		return -1;

	mail_index_buffer_convert_to_uids(t->view, t->expunges,
		sizeof(struct mail_transaction_expunge), TRUE);
	mail_index_buffer_convert_to_uids(t->view, t->updates,
		sizeof(struct mail_transaction_flag_update), TRUE);
	mail_index_buffer_convert_to_uids(t->view, t->cache_updates,
		sizeof(struct mail_transaction_cache_update), TRUE);
	return 0;
}

int mail_index_transaction_commit(struct mail_index_transaction *t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r)
{
	int ret;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_transaction_free(t);
		return -1;
	}

	if (t->last_update.uid1 != 0)
		mail_index_transaction_add_last(t);

	if (mail_index_transaction_convert_to_uids(t) < 0)
		ret = -1;
	else {
		ret = mail_transaction_log_append(t, log_file_seq_r,
						  log_file_offset_r);
	}

	mail_index_transaction_free(t);
	return ret;
}

void mail_index_transaction_rollback(struct mail_index_transaction *t)
{
        mail_index_transaction_free(t);
}

void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r)
{
        struct mail_index_record *rec;

	if (t->appends == NULL) {
		t->appends = buffer_create_dynamic(default_pool,
						   4096, (size_t)-1);
	}

	/* sequence number is visible only inside given view,
	   so let it generate it */
	if (t->last_new_seq != 0)
		*seq_r = ++t->last_new_seq;
	else {
		*seq_r = t->first_new_seq = t->last_new_seq =
			mail_index_view_get_message_count(t->view)+1;
	}

	rec = buffer_append_space_unsafe(t->appends, sizeof(*rec));
	memset(rec, 0, sizeof(*rec));
	rec->uid = uid;
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
        struct mail_transaction_expunge exp, *data;
	unsigned int idx, left_idx, right_idx;
	size_t size;

	i_assert(seq > 0 && seq <= mail_index_view_get_message_count(t->view));

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

		if (data[idx].uid1 < seq)
			left_idx = idx+1;
		else if (data[idx].uid1 > seq)
			right_idx = idx;
		else
			break;
	}

	if (data[idx].uid2 < seq)
		idx++;

        /* idx == size couldn't happen because we already handle it above */
	i_assert(idx < size && data[idx].uid1 >= seq);

	if (data[idx].uid1 <= seq && data[idx].uid2 >= seq) {
		/* already expunged */
		return;
	}

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
	size_t pos;

	if (t->first_new_seq != 0 && seq >= t->first_new_seq) {
		/* just appended message, modify it directly */
		i_assert(seq > 0 && seq <= t->last_new_seq);

		pos = (seq - t->first_new_seq) * sizeof(*rec);
		rec = buffer_get_space_unsafe(t->appends, pos, sizeof(*rec));
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

	i_assert(idx == size || data[idx].uid1 < update.uid1);

	/* insert it into buffer, split it in multiple parts if needed
	   to make sure the ordering stays the same */
	for (; idx < size; idx++) {
		if (data[idx].uid1 > update.uid2)
			break;

		/* partial */
		last = update.uid2;
		update.uid2 = data[idx].uid1-1;

		buffer_insert(t->updates, idx * sizeof(update),
			      &update, sizeof(update));
		data = buffer_get_modifyable_data(t->updates, NULL);
		size++;

		update.uid1 = update.uid2+1;
		update.uid2 = last;
	}

	buffer_insert(t->updates, idx * sizeof(update),
		      &update, sizeof(update));
}

void mail_index_update_cache(struct mail_index_transaction *t,
			     uint32_t seq, uint32_t offset)
{
	struct mail_transaction_cache_update *data, update;
	unsigned int idx, left_idx, right_idx;
	size_t size;

	if (t->cache_updates == NULL) {
		t->cache_updates = buffer_create_dynamic(default_pool,
							 1024, (size_t)-1);
	}

	data = buffer_get_modifyable_data(t->cache_updates, &size);
	size /= sizeof(*data);

	/* we're probably appending it, check */
	if (size == 0 || data[size-1].uid < seq)
		idx = size;
	else {
		idx = 0; left_idx = 0; right_idx = size;
		while (left_idx < right_idx) {
			idx = (left_idx + right_idx) / 2;

			if (data[idx].uid < seq)
				left_idx = idx+1;
			else if (data[idx].uid > seq)
				right_idx = idx;
			else {
				/* already there, update */
				data[idx].cache_offset = offset;
				return;
			}
		}
	}

	update.uid = seq;
	update.cache_offset = offset;
	buffer_insert(t->updates, idx * sizeof(update),
		      &update, sizeof(update));
}
