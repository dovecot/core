/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

/* Inside transaction we keep messages stored in sequences in uid fields.
   Before they're written to transaction log the sequences are changed to
   UIDs. This is because we're able to compress sequence ranges better. */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "seq-range-array.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <stdlib.h>
#include <time.h>

void (*hook_mail_index_transaction_created)
		(struct mail_index_transaction *t) = NULL;

static bool
mail_index_transaction_has_ext_changes(struct mail_index_transaction *t);

void mail_index_transaction_reset(struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *recs;
	struct mail_index_transaction_ext_hdr_update **ext_hdrs;
	unsigned i, count;

	if (array_is_created(&t->ext_rec_updates)) {
		recs = array_get_modifiable(&t->ext_rec_updates, &count);

		for (i = 0; i < count; i++) {
			if (array_is_created(&recs[i]))
				array_free(&recs[i]);
		}
		array_free(&t->ext_rec_updates);
	}
	if (array_is_created(&t->ext_hdr_updates)) {
		ext_hdrs = array_get_modifiable(&t->ext_hdr_updates, &count);

		for (i = 0; i < count; i++)
			i_free(ext_hdrs[i]);
		array_free(&t->ext_hdr_updates);
	}

	if (array_is_created(&t->keyword_updates)) {
		struct mail_index_transaction_keyword_update *u;

		u = array_get_modifiable(&t->keyword_updates, &count);

		for (i = 0; i < count; i++) {
			if (array_is_created(&u[i].add_seq))
				array_free(&u[i].add_seq);
			if (array_is_created(&u[i].remove_seq))
				array_free(&u[i].remove_seq);
		}
		array_free(&t->keyword_updates);
	}
	if (array_is_created(&t->keyword_resets))
		array_free(&t->keyword_resets);

	if (array_is_created(&t->appends))
		array_free(&t->appends);
	if (array_is_created(&t->expunges))
		array_free(&t->expunges);
	if (array_is_created(&t->updates))
		array_free(&t->updates);
	if (array_is_created(&t->ext_resizes))
		array_free(&t->ext_resizes);
	if (array_is_created(&t->ext_resets))
		array_free(&t->ext_resets);
	if (array_is_created(&t->ext_reset_ids))
		array_free(&t->ext_reset_ids);
	if (array_is_created(&t->ext_reset_atomic))
		array_free(&t->ext_reset_atomic);

	t->first_new_seq = mail_index_view_get_messages_count(t->view)+1;
	t->last_new_seq = 0;
	t->last_update_idx = 0;

	memset(t->pre_hdr_mask, 0, sizeof(t->pre_hdr_mask));
	memset(t->post_hdr_mask, 0, sizeof(t->post_hdr_mask));

	if (t->cache_trans_ctx != NULL)
		mail_cache_transaction_rollback(&t->cache_trans_ctx);

	t->appends_nonsorted = FALSE;
	t->pre_hdr_changed = FALSE;
	t->post_hdr_changed = FALSE;
	t->reset = FALSE;
	t->log_updates = FALSE;
	t->log_ext_updates = FALSE;
}

static bool mail_index_transaction_has_changes(struct mail_index_transaction *t)
{
	/* flag updates aren't included in log_updates */
	return array_is_created(&t->appends) ||
		array_is_created(&t->expunges) ||
		array_is_created(&t->keyword_resets) ||
		array_is_created(&t->keyword_updates) ||
		t->pre_hdr_changed || t->post_hdr_changed;
}

static void mail_index_transaction_free(struct mail_index_transaction *t)
{
	mail_index_transaction_reset(t);

	array_free(&t->module_contexts);
	mail_index_view_transaction_unref(t->view);
	mail_index_view_close(&t->view);
	i_free(t);
}

struct mail_index_view *
mail_index_transaction_get_view(struct mail_index_transaction *t)
{
	return t->view;
}

bool mail_index_transaction_is_expunged(struct mail_index_transaction *t,
					uint32_t seq)
{
	return array_is_created(&t->expunges) &&
		seq_range_exists(&t->expunges, seq);
}

void mail_index_transaction_ref(struct mail_index_transaction *t)
{
	t->refcount++;
}

void mail_index_transaction_unref(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	if (--t->refcount == 0)
		mail_index_transaction_free(t);
}

static int mail_index_seq_record_cmp(const void *key, const void *data)
{
	const uint32_t *seq_p = key;
	const uint32_t *data_seq = data;

	return *seq_p - *data_seq;
}

bool mail_index_seq_array_lookup(const ARRAY_TYPE(seq_array) *array,
				 uint32_t seq, unsigned int *idx_r)
{
	const void *base;
	unsigned int count;

	base = array_get(array, &count);
	return bsearch_insert_pos(&seq, base, count, array->arr.element_size,
				  mail_index_seq_record_cmp, idx_r);
}

static bool mail_index_seq_array_add(ARRAY_TYPE(seq_array) *array, uint32_t seq,
				     const void *record, size_t record_size,
				     void *old_record)
{
	void *p;
	unsigned int idx, aligned_record_size;

	/* records need to be 32bit aligned */
	aligned_record_size = (record_size + 3) & ~3;

	if (!array_is_created(array)) {
		array_create(array, default_pool,
			     sizeof(seq) + aligned_record_size,
			     1024 / (sizeof(seq) + aligned_record_size));
	}
	i_assert(array->arr.element_size == sizeof(seq) + aligned_record_size);

	if (mail_index_seq_array_lookup(array, seq, &idx)) {
		/* already there, update */
		p = array_idx_modifiable(array, idx);
		if (old_record != NULL) {
			/* save the old record before overwriting it */
			memcpy(old_record, PTR_OFFSET(p, sizeof(seq)),
			       record_size);
		}
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return TRUE;
	} else {
		/* insert */
                p = array_insert_space(array, idx);
		memcpy(p, &seq, sizeof(seq));
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return FALSE;
	}
}

static uint32_t
mail_index_transaction_get_uid(struct mail_index_transaction *t, uint32_t seq)
{
	const struct mail_index_record *rec;

	i_assert(seq > 0);

	if (seq >= t->first_new_seq)
		rec = mail_index_transaction_lookup(t, seq);
	else {
		i_assert(seq <= t->view->map->hdr.messages_count);
		rec = MAIL_INDEX_MAP_IDX(t->view->map, seq - 1);
	}
	i_assert(rec->uid != 0);
	return rec->uid;
}

static void
mail_index_convert_to_uids(struct mail_index_transaction *t,
			   ARRAY_TYPE(seq_array) *array)
{
	uint32_t *seq;
	unsigned int i, count;

	if (!array_is_created(array))
		return;

	count = array_count(array);
	for (i = 0; i < count; i++) {
		seq = array_idx_modifiable(array, i);
		*seq = mail_index_transaction_get_uid(t, *seq);
	}
}

static uint32_t
get_nonexpunged_uid2(struct mail_index_transaction *t,
		     uint32_t uid1, uint32_t seq1)
{
	seq1++;

	while (mail_index_transaction_get_uid(t, seq1) == uid1 + 1) {
		seq1++;
		uid1++;
	}
	return uid1;
}

static void
mail_index_convert_to_uid_ranges(struct mail_index_transaction *t,
				 ARRAY_TYPE(seq_range) *array)
{
	struct seq_range *range, *new_range;
	unsigned int i, count;
	uint32_t uid1, uid2;

	if (!array_is_created(array))
		return;

	count = array_count(array);
	for (i = 0; i < count; i++) {
		range = array_idx_modifiable(array, i);

		uid1 = mail_index_transaction_get_uid(t, range->seq1);
		uid2 = mail_index_transaction_get_uid(t, range->seq2);
		if (uid2 - uid1 == range->seq2 - range->seq1) {
			/* simple conversion */
			range->seq1 = uid1;
			range->seq2 = uid2;
		} else {
			/* remove expunged UIDs */
			new_range = array_insert_space(array, i);
			range = array_idx_modifiable(array, i + 1);
			count++;

			memcpy(new_range, range, array->arr.element_size);
			new_range->seq1 = uid1;
			new_range->seq2 = get_nonexpunged_uid2(t, uid1,
							       range->seq1);

			/* continue the range without the inserted seqs */
			range->seq1 += new_range->seq2 - new_range->seq1 + 1;
		}
	}
}

static void keyword_updates_convert_to_uids(struct mail_index_transaction *t)
{
        struct mail_index_transaction_keyword_update *updates;
	unsigned int i, count;

	if (!array_is_created(&t->keyword_updates))
		return;

	updates = array_get_modifiable(&t->keyword_updates, &count);
	for (i = 0; i < count; i++) {
		mail_index_convert_to_uid_ranges(t, &updates[i].add_seq);
		mail_index_convert_to_uid_ranges(t, &updates[i].remove_seq);
	}
}

static int
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *updates;
	unsigned int i, count;

	if (array_is_created(&t->ext_rec_updates)) {
		updates = array_get_modifiable(&t->ext_rec_updates, &count);
		for (i = 0; i < count; i++)
			mail_index_convert_to_uids(t, (void *)&updates[i]);
	}

        keyword_updates_convert_to_uids(t);

	mail_index_convert_to_uid_ranges(t, &t->expunges);
	mail_index_convert_to_uid_ranges(t, (void *)&t->updates);
	mail_index_convert_to_uid_ranges(t, &t->keyword_resets);
	return 0;
}

struct uid_map {
	uint32_t idx;
	uint32_t uid;
};

static int uid_map_cmp(const void *p1, const void *p2)
{
	const struct uid_map *m1 = p1, *m2 = p2;

	return m1->uid < m2->uid ? -1 :
		(m1->uid > m2->uid ? 1 : 0);
}

static void
mail_index_update_day_headers(struct mail_index_transaction *t)
{
	struct mail_index_header hdr;
	const struct mail_index_record *rec;
	const int max_days = N_ELEMENTS(hdr.day_first_uid);
	struct tm tm;
	time_t stamp;
	int i, days;

	hdr = *mail_index_get_header(t->view);
	rec = array_idx(&t->appends, 0);

	/* get beginning of today */
	tm = *localtime(&ioloop_time);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	stamp = mktime(&tm);
	i_assert(stamp != (time_t)-1);

	if ((time_t)hdr.day_stamp >= stamp)
		return;

	/* get number of days since last message */
	days = (stamp - hdr.day_stamp) / (3600*24);
	if (days > max_days)
		days = max_days;

	/* @UNSAFE: move days forward and fill the missing days with old
	   day_first_uid[0]. */
	memmove(hdr.day_first_uid + days, hdr.day_first_uid, max_days - days);
	for (i = 1; i < days; i++)
		hdr.day_first_uid[i] = hdr.day_first_uid[0];

	hdr.day_stamp = stamp;
	hdr.day_first_uid[0] = rec->uid;

	mail_index_update_header(t,
		offsetof(struct mail_index_header, day_stamp),
		&hdr.day_stamp, sizeof(hdr.day_stamp), FALSE);
	mail_index_update_header(t,
		offsetof(struct mail_index_header, day_first_uid),
		hdr.day_first_uid, sizeof(hdr.day_first_uid), FALSE);
}

static void
mail_index_transaction_sort_appends_ext(struct mail_index_transaction *t,
					const uint32_t *old_to_newseq_map)
{
	ARRAY_TYPE(seq_array) *ext_rec_arrays;
	ARRAY_TYPE(seq_array) *old_array;
	ARRAY_TYPE(seq_array) new_array;
	unsigned int ext_count;
	const uint32_t *ext_rec;
	uint32_t seq;
	unsigned int i, j, count;

	if (!array_is_created(&t->ext_rec_updates))
		return;

	ext_rec_arrays = array_get_modifiable(&t->ext_rec_updates, &count);
	for (j = 0; j < count; j++) {
		old_array = &ext_rec_arrays[j];
		if (!array_is_created(old_array))
			continue;

		ext_count = array_count(old_array);
		array_create(&new_array, default_pool,
			     old_array->arr.element_size, ext_count);
		for (i = 0; i < ext_count; i++) {
			ext_rec = array_idx(old_array, i);

			seq = *ext_rec < t->first_new_seq ? *ext_rec :
				old_to_newseq_map[*ext_rec - t->first_new_seq];
			mail_index_seq_array_add(&new_array, seq, ext_rec+1,
						 old_array->arr.element_size -
						 sizeof(*ext_rec), NULL);
		}
		array_free(old_array);
		ext_rec_arrays[j] = new_array;
	}
}

static void
sort_appends_seq_range(struct mail_index_transaction *t,
		       ARRAY_TYPE(seq_range) *array,
		       const uint32_t *old_to_newseq_map)
{
	struct seq_range *range, temp_range;
	ARRAY_TYPE(seq_range) old_seqs;
	uint32_t idx, idx1, idx2;
	unsigned int i, count;

	range = array_get_modifiable(array, &count);
	for (i = 0; i < count; i++) {
		if (range[i].seq2 >= t->first_new_seq)
			break;
	}
	if (i == count) {
		/* nothing to do */
		return;
	}

	i_array_init(&old_seqs, count - i);
	if (range[i].seq1 < t->first_new_seq) {
		temp_range.seq1 = t->first_new_seq;
		temp_range.seq2 = range[i].seq2;
		array_append(&old_seqs, &temp_range, 1);
		range[i].seq2 = t->first_new_seq - 1;
		i++;
	}
	array_append(&old_seqs, &range[i], count - i);
	array_delete(array, i, count - i);

	range = array_get_modifiable(&old_seqs, &count);
	for (i = 0; i < count; i++) {
		idx1 = range[i].seq1 - t->first_new_seq;
		idx2 = range[i].seq2 - t->first_new_seq;
		for (idx = idx1; idx <= idx2; idx++)
			seq_range_array_add(array, 0, old_to_newseq_map[idx]);
	}
	array_free(&old_seqs);
}

static void
mail_index_transaction_sort_appends_keywords(struct mail_index_transaction *t,
					     const uint32_t *old_to_newseq_map)
{
	struct mail_index_transaction_keyword_update *updates;
	unsigned int i, count;

	if (array_is_created(&t->keyword_updates)) {
		updates = array_get_modifiable(&t->keyword_updates, &count);
		for (i = 0; i < count; i++) {
			if (array_is_created(&updates->add_seq)) {
				sort_appends_seq_range(t, &updates[i].add_seq,
						       old_to_newseq_map);
			}
			if (array_is_created(&updates->remove_seq)) {
				sort_appends_seq_range(t,
						       &updates[i].remove_seq,
						       old_to_newseq_map);
			}
		}
	}

	if (array_is_created(&t->keyword_resets)) {
		sort_appends_seq_range(t, &t->keyword_resets,
				       old_to_newseq_map);
	}
}

void mail_index_transaction_sort_appends(struct mail_index_transaction *t)
{
	struct mail_index_record *recs, *sorted_recs;
	struct uid_map *new_uid_map;
	uint32_t *old_to_newseq_map;
	unsigned int i, count;

	if (!t->appends_nonsorted)
		return;

	/* first make a copy of the UIDs and map them to sequences */
	recs = array_get_modifiable(&t->appends, &count);
	i_assert(count > 0);

	new_uid_map = i_new(struct uid_map, count);
	for (i = 0; i < count; i++) {
		new_uid_map[i].idx = i;
		new_uid_map[i].uid = recs[i].uid;
	}

	/* now sort the UID map */
	qsort(new_uid_map, count, sizeof(*new_uid_map), uid_map_cmp);

	/* sort mail records */
	sorted_recs = i_new(struct mail_index_record, count);
	sorted_recs[0] = recs[new_uid_map[0].idx];
	for (i = 1; i < count; i++) {
		sorted_recs[i] = recs[new_uid_map[i].idx];
		if (sorted_recs[i].uid == sorted_recs[i-1].uid)
			i_panic("Duplicate UIDs added in transaction");
	}
	buffer_write(t->appends.arr.buffer, 0, sorted_recs,
		     sizeof(*sorted_recs) * count);
	i_free(sorted_recs);

	old_to_newseq_map = i_new(uint32_t, count);
	for (i = 0; i < count; i++)
		old_to_newseq_map[new_uid_map[i].idx] = i + t->first_new_seq;
	i_free(new_uid_map);

	mail_index_transaction_sort_appends_ext(t, old_to_newseq_map);
	mail_index_transaction_sort_appends_keywords(t, old_to_newseq_map);
	i_free(old_to_newseq_map);

	t->appends_nonsorted = FALSE;
}

uint32_t mail_index_transaction_get_next_uid(struct mail_index_transaction *t)
{
	const struct mail_index_header *hdr;
	const struct mail_index_record *recs;
	unsigned int count, offset;
	uint32_t next_uid;

	next_uid = t->reset ? 1 : t->view->map->hdr.next_uid;
	if (array_is_created(&t->appends)) {
		/* get next_uid from appends if they have UIDs */
		mail_index_transaction_sort_appends(t);

		recs = array_get(&t->appends, &count);
		if (count > 0 && recs[count-1].uid != 0) {
			i_assert(recs[count-1].uid >= next_uid);
			next_uid = recs[count-1].uid + 1;
		}
	}

	/* see if it's been updated in pre/post header changes */
	offset = offsetof(struct mail_index_header, next_uid);
	if (t->post_hdr_mask[offset] != 0) {
		hdr = (const void *)t->post_hdr_change;
		if (hdr->next_uid > next_uid)
			next_uid = hdr->next_uid;
	}
	if (t->pre_hdr_mask[offset] != 0) {
		hdr = (const void *)t->pre_hdr_change;
		if (hdr->next_uid > next_uid)
			next_uid = hdr->next_uid;
	}
	return next_uid;
}

static int mail_index_transaction_commit_v(struct mail_index_transaction *t,
					   uint32_t *log_file_seq_r,
					   uoff_t *log_file_offset_r)
{
	int ret;

	i_assert(t->first_new_seq >
		 mail_index_view_get_messages_count(t->view));

	if (t->cache_trans_ctx != NULL)
		mail_cache_transaction_commit(&t->cache_trans_ctx);

	if (array_is_created(&t->appends)) {
		mail_index_transaction_sort_appends(t);
		mail_index_update_day_headers(t);
	}

	if (mail_index_transaction_convert_to_uids(t) < 0)
		ret = -1;
	else {
		ret = mail_transaction_log_append(t, log_file_seq_r,
						  log_file_offset_r);
	}

	if (ret == 0 && !t->view->index->syncing) {
		/* if we're committing a normal transaction, we want to
		   have those changes in the index mapping immediately. this
		   is especially important when committing cache offset
		   updates.

		   however if we're syncing the index now, the mapping must
		   be done later as MAIL_INDEX_SYNC_HANDLER_FILE so that
		   expunge handlers get run for the newly expunged messages
		   (and sync handlers that require HANDLER_FILE as well). */
		(void)mail_index_refresh(t->view->index);
	}

	mail_index_transaction_unref(&t);
	return ret;
}

static void mail_index_transaction_rollback_v(struct mail_index_transaction *t)
{
	if (t->cache_trans_ctx != NULL)
		mail_cache_transaction_rollback(&t->cache_trans_ctx);
        mail_index_transaction_unref(&t);
}

int mail_index_transaction_commit(struct mail_index_transaction **_t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r)
{
	struct mail_index_transaction *t = *_t;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_transaction_rollback(_t);
		return -1;
	}

	*_t = NULL;
	return t->v.commit(t, log_file_seq_r, log_file_offset_r);
}

void mail_index_transaction_rollback(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	t->v.rollback(t);
}

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq >= t->first_new_seq && seq <= t->last_new_seq);

	return array_idx_modifiable(&t->appends, seq - t->first_new_seq);
}

void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r)
{
        struct mail_index_record *rec;

	i_assert(!t->no_appends);

	t->log_updates = TRUE;

	if (!array_is_created(&t->appends))
		i_array_init(&t->appends, 32);

	/* sequence number is visible only inside given view,
	   so let it generate it */
	if (t->last_new_seq != 0)
		*seq_r = ++t->last_new_seq;
	else
		*seq_r = t->last_new_seq = t->first_new_seq;

	rec = array_append_space(&t->appends);
	if (uid != 0) {
		rec->uid = uid;
		if (!t->appends_nonsorted &&
		    t->last_new_seq != t->first_new_seq) {
			/* if previous record's UID is larger than this one,
			   we'll have to sort the appends later */
			rec = mail_index_transaction_lookup(t, *seq_r - 1);
			if (rec->uid > uid)
				t->appends_nonsorted = TRUE;
			else if (rec->uid == uid)
				i_panic("Duplicate UIDs added in transaction");
		}
	}
}

void mail_index_append_assign_uids(struct mail_index_transaction *t,
				   uint32_t first_uid, uint32_t *next_uid_r)
{
	struct mail_index_record *recs;
	unsigned int i, count;

	i_assert(first_uid != 0);

	if (!array_is_created(&t->appends))
		return;

	recs = array_get_modifiable(&t->appends, &count);

	/* find the first mail with uid = 0 */
	for (i = 0; i < count; i++) {
		if (recs[i].uid == 0)
			break;
	}

	for (; i < count; i++) {
		i_assert(recs[i].uid == 0);
		recs[i].uid = first_uid++;
	}

	*next_uid_r = first_uid;
}

static void
mail_index_expunge_last_append(struct mail_index_transaction *t, uint32_t seq)
{
	ARRAY_TYPE(seq_array) *seqs;
	struct mail_index_transaction_keyword_update *kw_updates;
	unsigned int i, idx, count;

	i_assert(seq == t->last_new_seq);

	/* remove extension updates */
	if (array_is_created(&t->ext_rec_updates)) {
		seqs = array_get_modifiable(&t->ext_rec_updates, &count);
		for (i = 0; i < count; i++) {
			if (array_is_created(&seqs[i]) &&
			    mail_index_seq_array_lookup(&seqs[i], seq, &idx))
				array_delete(&seqs[i], idx, 1);
		}
		t->log_ext_updates = mail_index_transaction_has_ext_changes(t);
	}
	/* remove keywords */
	if (array_is_created(&t->keyword_resets))
		seq_range_array_remove(&t->keyword_resets, seq);
	if (array_is_created(&t->keyword_updates)) {
		kw_updates = array_get_modifiable(&t->keyword_updates, &count);
		for (i = 0; i < count; i++) {
			if (array_is_created(&kw_updates[i].add_seq)) {
				seq_range_array_remove(&kw_updates[i].add_seq,
						       seq);
			}
			if (array_is_created(&kw_updates[i].remove_seq)) {
				seq_range_array_remove(
					&kw_updates[i].remove_seq, seq);
			}
		}
	}

	/* and finally remove the append itself */
	array_delete(&t->appends, seq - t->first_new_seq, 1);
	t->last_new_seq--;
	if (t->first_new_seq > t->last_new_seq) {
		t->last_new_seq = 0;
		t->appends_nonsorted = FALSE;
		array_free(&t->appends);
	}
	t->log_updates = mail_index_transaction_has_changes(t);
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq > 0);
	if (seq >= t->first_new_seq) {
		/* we can handle only the last append. otherwise we'd have to
		   renumber sequences and that gets tricky. for now this is
		   enough, since we typically want to expunge all the
		   appends. */
		mail_index_expunge_last_append(t, seq);
	} else {
		t->log_updates = TRUE;

		/* expunges is a sorted array of {seq1, seq2, ..}, .. */
		seq_range_array_add(&t->expunges, 128, seq);
	}
}

static bool
mail_transaction_update_want_add(struct mail_index_transaction *t,
				 const struct mail_transaction_flag_update *u)
{
	const struct mail_index_record *rec;
	uint32_t seq;
	
	if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES) == 0)
		return TRUE;

	for (seq = u->uid1; seq <= u->uid2; seq++) {
		rec = mail_index_lookup(t->view, seq);
		if ((rec->flags & u->add_flags) != u->add_flags ||
		    (rec->flags & u->remove_flags) != 0)
			return TRUE;
	}

	return FALSE;
}

static void
mail_index_insert_flag_update(struct mail_index_transaction *t,
			      struct mail_transaction_flag_update u,
			      uint32_t left_idx, uint32_t right_idx)
{
	struct mail_transaction_flag_update *updates, tmp_update;
	unsigned int count;
	uint32_t idx, move;

	updates = array_get_modifiable(&t->updates, &count);

	i_assert(left_idx <= right_idx && right_idx <= count);

	/* find the first update with either overlapping range,
	   or the update which will come after our insert */
	idx = left_idx;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (updates[idx].uid2 < u.uid1)
			left_idx = idx+1;
		else if (updates[idx].uid1 > u.uid1)
			right_idx = idx;
		else
			break;
	}
	if (idx < count && updates[idx].uid2 < u.uid1)
		idx++;

	/* overlapping ranges, split/merge them */
	i_assert(idx == 0 || updates[idx-1].uid2 < u.uid1);
	i_assert(idx == count || updates[idx].uid2 >= u.uid1);

	for (; idx < count && u.uid2 >= updates[idx].uid1; idx++) {
		if (u.uid1 != updates[idx].uid1 &&
		    (updates[idx].add_flags != u.add_flags ||
		     updates[idx].remove_flags != u.remove_flags)) {
			if (u.uid1 < updates[idx].uid1) {
				/* insert new update */
				tmp_update = u;
				tmp_update.uid2 = updates[idx].uid1 - 1;
				move = 0;
			} else {
				/* split existing update from beginning */
				tmp_update = updates[idx];
				tmp_update.uid2 = u.uid1 - 1;
				updates[idx].uid1 = u.uid1;
				move = 1;
			}

			i_assert(tmp_update.uid1 <= tmp_update.uid2);
			i_assert(updates[idx].uid1 <= updates[idx].uid2);

			if (mail_transaction_update_want_add(t, &tmp_update)) {
				array_insert(&t->updates, idx, &tmp_update, 1);
				updates = array_get_modifiable(&t->updates,
							       &count);
				idx += move;
			}
		} else if (u.uid1 < updates[idx].uid1) {
			updates[idx].uid1 = u.uid1;
		}

		if (u.uid2 < updates[idx].uid2 &&
		    (updates[idx].add_flags != u.add_flags ||
		     updates[idx].remove_flags != u.remove_flags)) {
			/* split existing update from end */
			tmp_update = updates[idx];
			tmp_update.uid2 = u.uid2;
			updates[idx].uid1 = u.uid2 + 1;

			i_assert(tmp_update.uid1 <= tmp_update.uid2);
			i_assert(updates[idx].uid1 <= updates[idx].uid2);

			if (mail_transaction_update_want_add(t, &tmp_update))
				array_insert(&t->updates, idx, &tmp_update, 1);
			updates = array_get_modifiable(&t->updates, &count);
		}

		updates[idx].add_flags =
			(updates[idx].add_flags | u.add_flags) &
			~u.remove_flags;
		updates[idx].remove_flags =
			(updates[idx].remove_flags | u.remove_flags) &
			~u.add_flags;
		u.uid1 = updates[idx].uid2 + 1;

		if (updates[idx].add_flags == 0 &&
		    updates[idx].remove_flags == 0) {
			/* we can remove this update completely */
			array_delete(&t->updates, idx, 1);
			updates = array_get_modifiable(&t->updates, &count);
			idx--;
		}

		if (u.uid1 > u.uid2) {
			/* break here before idx++ so last_update_idx is set
			   correctly */
			break;
		}
	}
	i_assert(idx <= count);

	if (u.uid1 <= u.uid2) {
		i_assert(idx == 0 || updates[idx-1].uid2 < u.uid1);
		i_assert(idx == count || updates[idx].uid1 > u.uid2);
		if (mail_transaction_update_want_add(t, &u)) {
			array_insert(&t->updates, idx, &u, 1);
			count++;
		}
	}
	t->last_update_idx = idx == count ? count-1 : idx;
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

void mail_index_update_flags_range(struct mail_index_transaction *t,
				   uint32_t seq1, uint32_t seq2,
				   enum modify_type modify_type,
				   enum mail_flags flags)
{
	struct mail_index_record *rec;
	struct mail_transaction_flag_update u, *last_update;
	unsigned int first_idx, count;

	if (seq2 >= t->first_new_seq) {
		/* updates for appended messages, modify them directly */
		uint32_t seq;

		for (seq = I_MAX(t->first_new_seq, seq1); seq <= seq2; seq++) {
			rec = mail_index_transaction_lookup(t, seq);
			mail_index_record_modify_flags(rec, modify_type, flags);
		}
		if (seq1 >= t->first_new_seq)
			return;

		/* range contains also existing messages. update them next. */
		seq2 = t->first_new_seq - 1;
	}

	i_assert(seq1 <= seq2 && seq1 > 0);
	i_assert(seq2 <= mail_index_view_get_messages_count(t->view));

	memset(&u, 0, sizeof(u));
	u.uid1 = seq1;
	u.uid2 = seq2;

	switch (modify_type) {
	case MODIFY_REPLACE:
		u.add_flags = flags;
		u.remove_flags = ~flags & MAIL_INDEX_FLAGS_MASK;
		break;
	case MODIFY_ADD:
		u.add_flags = flags;
		break;
	case MODIFY_REMOVE:
		u.remove_flags = flags;
		break;
	}

	if (!array_is_created(&t->updates)) {
		i_array_init(&t->updates, 256);
		if (mail_transaction_update_want_add(t, &u))
			array_append(&t->updates, &u, 1);
		return;
	}

	last_update = array_get_modifiable(&t->updates, &count);
	if (t->last_update_idx < count) {
		/* fast path - hopefully we're updating the next message,
		   or a message that is to be appended as last update */
		last_update += t->last_update_idx;
		if (seq1 - 1 == last_update->uid2) {
			if (u.add_flags == last_update->add_flags &&
			    u.remove_flags == last_update->remove_flags &&
			    (t->last_update_idx + 1 == count ||
			     last_update[1].uid1 > seq2)) {
				/* we can just update the UID range */
				if (mail_transaction_update_want_add(t, &u))
					last_update->uid2 = seq2;
				return;
			}
		} else if (seq1 > last_update->uid2) {
			/* hopefully we can just append it */
			t->last_update_idx++;
			last_update++;
		}
	}

	if (t->last_update_idx == count) {
		if (mail_transaction_update_want_add(t, &u))
			array_append(&t->updates, &u, 1);
		else if (t->last_update_idx > 0)
			t->last_update_idx--;
	} else {
		i_assert(t->last_update_idx < count);

		/* slow path */
		if (seq1 > last_update->uid2) {
			/* added after this */
			first_idx = t->last_update_idx + 1;
		} else {
			/* added before this or on top of this */
			first_idx = 0;
			count = t->last_update_idx + 1;
		}
		mail_index_insert_flag_update(t, u, first_idx, count);
	}
}

void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags)
{
	mail_index_update_flags_range(t, seq, seq, modify_type, flags);
}

void mail_index_update_header(struct mail_index_transaction *t,
			      size_t offset, const void *data, size_t size,
			      bool prepend)
{
	i_assert(offset < sizeof(t->pre_hdr_change));
	i_assert(size <= sizeof(t->pre_hdr_change) - offset);

	t->log_updates = TRUE;

	if (prepend) {
		t->pre_hdr_changed = TRUE;
		memcpy(t->pre_hdr_change + offset, data, size);
		for (; size > 0; size--)
			t->pre_hdr_mask[offset++] = 1;
	} else {
		t->post_hdr_changed = TRUE;
		memcpy(t->post_hdr_change + offset, data, size);
		for (; size > 0; size--)
			t->post_hdr_mask[offset++] = 1;
	}
}

void mail_index_ext_resize(struct mail_index_transaction *t, uint32_t ext_id,
			   uint32_t hdr_size, uint16_t record_size,
			   uint16_t record_align)
{
	struct mail_transaction_ext_intro intro;
	uint32_t old_record_size, old_record_align;

	memset(&intro, 0, sizeof(intro));

	/* get ext_id from transaction's map if it's there */
	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &intro.ext_id)) {
		/* have to create it */
		const struct mail_index_registered_ext *rext;

		intro.ext_id = (uint32_t)-1;
		rext = array_idx(&t->view->index->extensions, ext_id);
		old_record_size = rext->record_size;
		old_record_align = rext->record_align;
	} else {
		const struct mail_index_ext *ext;

		ext = array_idx(&t->view->map->extensions, intro.ext_id);
		old_record_size = ext->record_size;
		old_record_align = ext->record_align;
	}

	/* allow only header size changes if extension records have already
	   been changed in transaction */
	i_assert(!array_is_created(&t->ext_rec_updates) ||
		 (old_record_size == record_size &&
		  old_record_align == record_align));

	t->log_ext_updates = TRUE;

	if (!array_is_created(&t->ext_resizes))
		i_array_init(&t->ext_resizes, ext_id + 2);

	intro.hdr_size = hdr_size;
	intro.record_size = record_size;
	intro.record_align = record_align;
	intro.name_size = 1;
	array_idx_set(&t->ext_resizes, ext_id, &intro);
}

void mail_index_ext_reset(struct mail_index_transaction *t, uint32_t ext_id,
			  uint32_t reset_id, bool clear_data)
{
	struct mail_transaction_ext_reset reset;

	i_assert(reset_id != 0);

	memset(&reset, 0, sizeof(reset));
	reset.new_reset_id = reset_id;
	reset.preserve_data = !clear_data;

	mail_index_ext_set_reset_id(t, ext_id, reset_id);

	if (!array_is_created(&t->ext_resets))
		i_array_init(&t->ext_resets, ext_id + 2);
	array_idx_set(&t->ext_resets, ext_id, &reset);
	t->log_ext_updates = TRUE;
}

void mail_index_ext_reset_inc(struct mail_index_transaction *t, uint32_t ext_id,
			      uint32_t prev_reset_id, bool clear_data)
{
	uint32_t expected_reset_id = prev_reset_id + 1;

	mail_index_ext_reset(t, ext_id, (uint32_t)-1, clear_data);

	if (!array_is_created(&t->ext_reset_atomic))
		i_array_init(&t->ext_reset_atomic, ext_id + 2);
	array_idx_set(&t->ext_reset_atomic, ext_id, &expected_reset_id);
}

static bool
mail_index_transaction_has_ext_changes(struct mail_index_transaction *t)
{
	unsigned int i, count;

	if (array_is_created(&t->ext_rec_updates)) {
		const ARRAY_TYPE(seq_array) *array;

		array = array_get(&t->ext_rec_updates, &count);
		for (i = 0; i < count; i++) {
			if (array_is_created(&array[i]))
				return TRUE;
		}
	}
	if (array_is_created(&t->ext_hdr_updates)) {
		struct mail_index_transaction_ext_hdr_update *const *hdr;

		hdr = array_get(&t->ext_hdr_updates, &count);
		for (i = 0; i < count; i++) {
			if (hdr[i] != NULL)
				return TRUE;
		}
	}
	if (array_is_created(&t->ext_resets)) {
		const struct mail_transaction_ext_reset *resets;

		resets = array_get(&t->ext_resets, &count);
		for (i = 0; i < count; i++) {
			if (resets[i].new_reset_id != 0)
				return TRUE;
		}
	}
	if (array_is_created(&t->ext_resizes)) {
		const struct mail_transaction_ext_intro *resizes;

		resizes = array_get(&t->ext_resizes, &count);
		for (i = 0; i < count; i++) {
			if (resizes[i].name_size > 0)
				return TRUE;
		}
	}
	return FALSE;
}

void mail_index_ext_set_reset_id(struct mail_index_transaction *t,
				 uint32_t ext_id, uint32_t reset_id)
{
	if (array_is_created(&t->ext_rec_updates) &&
	    ext_id < array_count(&t->ext_rec_updates)) {
		/* if extension records have been updated, clear them */
		ARRAY_TYPE(seq_array) *array;

		array = array_idx_modifiable(&t->ext_rec_updates, ext_id);
		if (array_is_created(array))
			array_clear(array);
	}
	if (array_is_created(&t->ext_hdr_updates) &&
	    ext_id < array_count(&t->ext_hdr_updates)) {
		/* if extension headers have been updated, clear them */
		struct mail_index_transaction_ext_hdr_update **hdr;

		hdr = array_idx_modifiable(&t->ext_hdr_updates, ext_id);
		if (*hdr != NULL)
			i_free_and_null(*hdr);
	}
	if (array_is_created(&t->ext_resets) &&
	    ext_id < array_count(&t->ext_resets)) {
		/* clear resets */
		array_idx_clear(&t->ext_resets, ext_id);
	}
	if (array_is_created(&t->ext_resizes) &&
	    ext_id < array_count(&t->ext_resizes)) {
		/* clear resizes */
		array_idx_clear(&t->ext_resizes, ext_id);
	}

	if (!array_is_created(&t->ext_reset_ids))
		i_array_init(&t->ext_reset_ids, ext_id + 2);
	array_idx_set(&t->ext_reset_ids, ext_id, &reset_id);

	t->log_ext_updates = mail_index_transaction_has_ext_changes(t);
}

void mail_index_update_header_ext(struct mail_index_transaction *t,
				  uint32_t ext_id, size_t offset,
				  const void *data, size_t size)
{
	struct mail_index_transaction_ext_hdr_update *hdr, **pos;

	hdr = i_malloc(sizeof(*hdr) + size);
	hdr->ext_id = ext_id;
	hdr->offset = offset;
	hdr->size = size;
	memcpy(hdr + 1, data, size);

	if (!array_is_created(&t->ext_hdr_updates))
		i_array_init(&t->ext_hdr_updates, ext_id + 2);

	pos = array_idx_modifiable(&t->ext_hdr_updates, ext_id);
	if (*pos != NULL) {
		i_panic("mail_index_update_header_ext() doesn't currently "
			"support multiple updates to the same ext header");
	}
	*pos = hdr;

	t->log_ext_updates = TRUE;
}

void mail_index_update_ext(struct mail_index_transaction *t, uint32_t seq,
			   uint32_t ext_id, const void *data, void *old_data_r)
{
	struct mail_index *index = t->view->index;
        const struct mail_index_registered_ext *rext;
	const struct mail_transaction_ext_intro *intro;
	uint16_t record_size;
	ARRAY_TYPE(seq_array) *array;
	unsigned int count;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(ext_id < array_count(&index->extensions));

	t->log_ext_updates = TRUE;

	if (!array_is_created(&t->ext_resizes)) {
		intro = NULL;
		count = 0;
	} else {
		intro = array_get(&t->ext_resizes, &count);
	}
	if (ext_id < count && intro[ext_id].name_size != 0) {
		/* resized record */
		record_size = intro[ext_id].record_size;
	} else {
		rext = array_idx(&index->extensions, ext_id);
		record_size = rext->record_size;
	}

	if (!array_is_created(&t->ext_rec_updates))
		i_array_init(&t->ext_rec_updates, ext_id + 2);
	array = array_idx_modifiable(&t->ext_rec_updates, ext_id);

	/* @UNSAFE */
	if (!mail_index_seq_array_add(array, seq, data, record_size,
				      old_data_r)) {
		/* not found, clear old_data if it was given */
		if (old_data_r != NULL)
			memset(old_data_r, 0, record_size);
	}
}

struct mail_keywords *
mail_index_keywords_create(struct mail_index *index,
			   const char *const keywords[])
{
	struct mail_keywords *k;
	unsigned int src, dest, i, count;

	count = str_array_length(keywords);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(sizeof(struct mail_keywords) +
		     (sizeof(k->idx) * (count-1)));
	k->index = index;

	/* look up the keywords from index. they're never removed from there
	   so we can permanently store indexes to them. */
	for (src = dest = 0; src < count; src++) {
		mail_index_keyword_lookup_or_create(index, keywords[src],
						    &k->idx[dest]);
		/* ignore if this is a duplicate */
		for (i = 0; i < src; i++) {
			if (k->idx[i] == k->idx[dest])
				break;
		}
		if (i == src)
			dest++;
	}
	k->count = dest;
	return k;
}

struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index *index,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes)
{
	struct mail_keywords *k;
	const unsigned int *indexes;
	unsigned int src, dest, i, count;

	indexes = array_get(keyword_indexes, &count);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(sizeof(struct mail_keywords) +
		     (sizeof(k->idx) * (count-1)));
	k->index = index;

	/* copy but skip duplicates */
	for (src = dest = 0; src < count; src++) {
		for (i = 0; i < src; i++) {
			if (k->idx[i] == indexes[src])
				break;
		}
		if (i == src)
			k->idx[dest++] = indexes[src];
	}
	k->count = dest;
	return k;
}

void mail_index_keywords_free(struct mail_keywords **keywords)
{
	i_free(*keywords);
	*keywords = NULL;
}

static bool
keyword_update_has_changes(struct mail_index_transaction *t, uint32_t seq,
			   enum modify_type modify_type,
			   struct mail_keywords *keywords)
{
	struct mail_index_transaction_keyword_update *u;
	ARRAY_TYPE(keyword_indexes) existing;
	const unsigned int *existing_idx;
	unsigned int i, j, existing_count;
	bool found;

	t_array_init(&existing, 32);
	if (seq < t->first_new_seq)
		mail_index_lookup_keywords(t->view, seq, &existing);
	existing_idx = array_get(&existing, &existing_count);

	if (modify_type == MODIFY_REPLACE && existing_count != keywords->count)
		return TRUE;

	for (i = 0; i < keywords->count; i++) {
		u = array_idx_modifiable(&t->keyword_updates,
					 keywords->idx[i]);
		if (array_is_created(&u->add_seq) ||
		    array_is_created(&u->remove_seq))
			return TRUE;

		found = FALSE;
		for (j = 0; j < existing_count; j++) {
			if (existing_idx[j] == keywords->idx[i]) {
				found = TRUE;
				break;
			}
		}
		switch (modify_type) {
		case MODIFY_ADD:
		case MODIFY_REPLACE:
			if (!found)
				return TRUE;
			break;
		case MODIFY_REMOVE:
			if (found)
				return TRUE;
			break;
		}
	}
	return FALSE;
}

void mail_index_update_keywords(struct mail_index_transaction *t, uint32_t seq,
				enum modify_type modify_type,
				struct mail_keywords *keywords)
{
	struct mail_index_transaction_keyword_update *u;
	unsigned int i, ku_count;
	bool changed;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(keywords->count > 0 || modify_type == MODIFY_REPLACE);
	i_assert(keywords->index == t->view->index);

	if (!array_is_created(&t->keyword_updates) && keywords->count > 0) {
		uint32_t max_idx = keywords->idx[keywords->count-1];

		i_array_init(&t->keyword_updates, max_idx + 1);
	}

	if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES) != 0) {
		T_BEGIN {
			changed = keyword_update_has_changes(t, seq,
							     modify_type,
							     keywords);
		} T_END;
		if (!changed)
			return;
	}

	/* Update add_seq and remove_seq arrays which describe the keyword
	   changes. Don't bother updating remove_seq or keyword resets for
	   newly added messages since they default to not having any
	   keywords anyway. */
	switch (modify_type) {
	case MODIFY_ADD:
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_add(&u->add_seq, 16, seq);
			seq_range_array_remove(&u->remove_seq, seq);
		}
		break;
	case MODIFY_REMOVE:
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_remove(&u->add_seq, seq);
			if (seq < t->first_new_seq)
				seq_range_array_add(&u->remove_seq, 16, seq);
		}
		break;
	case MODIFY_REPLACE:
		/* Remove sequence from all add/remove arrays */
		if (array_is_created(&t->keyword_updates)) {
			u = array_get_modifiable(&t->keyword_updates,
						 &ku_count);
			for (i = 0; i < ku_count; i++) {
				seq_range_array_remove(&u[i].add_seq, seq);
				seq_range_array_remove(&u[i].remove_seq, seq);
			}
		}
		/* Add the wanted keyword back */
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_add(&u->add_seq, 16, seq);
		}

		if (seq < t->first_new_seq)
			seq_range_array_add(&t->keyword_resets, 16, seq);
		break;
	}

	t->log_updates = TRUE;
}

void mail_index_reset(struct mail_index_transaction *t)
{
	mail_index_transaction_reset(t);

	t->reset = TRUE;
}

struct mail_index_transaction_vfuncs trans_vfuncs = {
	mail_index_transaction_commit_v,
	mail_index_transaction_rollback_v
};

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     enum mail_index_transaction_flags flags)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);
 	mail_index_view_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->v = trans_vfuncs;
	t->view = view;
	t->flags = flags;
	t->sync_transaction = view->index_sync_view;

	if (view->syncing) {
		/* transaction view cannot work if new records are being added
		   in two places. make sure it doesn't happen. */
		t->no_appends = TRUE;
		t->first_new_seq = (uint32_t)-1;
	} else {
		t->first_new_seq =
			mail_index_view_get_messages_count(t->view) + 1;
	}

	i_array_init(&t->module_contexts,
		     I_MIN(5, mail_index_module_register.id));

	if (hook_mail_index_transaction_created != NULL)
		hook_mail_index_transaction_created(t);
	return t;
}
