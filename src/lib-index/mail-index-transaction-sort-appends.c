/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-index-private.h"
#include "mail-index-transaction-private.h"

#include <stdlib.h>

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
mail_index_transaction_sort_appends_ext(ARRAY_TYPE(seq_array_array) *updates,
					uint32_t first_new_seq,
					const uint32_t *old_to_newseq_map)
{
	ARRAY_TYPE(seq_array) *ext_rec_arrays;
	ARRAY_TYPE(seq_array) *old_array;
	ARRAY_TYPE(seq_array) new_array;
	unsigned int ext_count;
	const uint32_t *ext_rec;
	uint32_t seq;
	unsigned int i, j, count;

	if (!array_is_created(updates))
		return;

	ext_rec_arrays = array_get_modifiable(updates, &count);
	for (j = 0; j < count; j++) {
		old_array = &ext_rec_arrays[j];
		if (!array_is_created(old_array))
			continue;

		ext_count = array_count(old_array);
		array_create(&new_array, default_pool,
			     old_array->arr.element_size, ext_count);
		for (i = 0; i < ext_count; i++) {
			ext_rec = array_idx(old_array, i);

			seq = *ext_rec < first_new_seq ? *ext_rec :
				old_to_newseq_map[*ext_rec - first_new_seq];
			mail_index_seq_array_add(&new_array, seq, ext_rec+1,
						 old_array->arr.element_size -
						 sizeof(*ext_rec), NULL);
		}
		array_free(old_array);
		ext_rec_arrays[j] = new_array;
	}
}

static void
sort_appends_seq_range(ARRAY_TYPE(seq_range) *array, uint32_t first_new_seq,
		       const uint32_t *old_to_newseq_map)
{
	struct seq_range *range, temp_range;
	ARRAY_TYPE(seq_range) old_seqs;
	uint32_t idx, idx1, idx2;
	unsigned int i, count;

	range = array_get_modifiable(array, &count);
	for (i = 0; i < count; i++) {
		if (range[i].seq2 >= first_new_seq)
			break;
	}
	if (i == count) {
		/* nothing to do */
		return;
	}

	i_array_init(&old_seqs, count - i);
	if (range[i].seq1 < first_new_seq) {
		temp_range.seq1 = first_new_seq;
		temp_range.seq2 = range[i].seq2;
		array_append(&old_seqs, &temp_range, 1);
		range[i].seq2 = first_new_seq - 1;
		i++;
	}
	array_append(&old_seqs, &range[i], count - i);
	array_delete(array, i, count - i);

	range = array_get_modifiable(&old_seqs, &count);
	for (i = 0; i < count; i++) {
		idx1 = range[i].seq1 - first_new_seq;
		idx2 = range[i].seq2 - first_new_seq;
		for (idx = idx1; idx <= idx2; idx++)
			seq_range_array_add(array, 0, old_to_newseq_map[idx]);
	}
	array_free(&old_seqs);
}

static void
mail_index_transaction_sort_appends_keywords(struct mail_index_transaction *t,
					     const uint32_t *old_to_newseq_map)
{
	struct mail_index_transaction_keyword_update *update;

	if (array_is_created(&t->keyword_updates)) {
		array_foreach_modifiable(&t->keyword_updates, update) {
			if (array_is_created(&update->add_seq)) {
				sort_appends_seq_range(&update->add_seq,
						       t->first_new_seq,
						       old_to_newseq_map);
			}
			if (array_is_created(&update->remove_seq)) {
				sort_appends_seq_range(&update->remove_seq,
						       t->first_new_seq,
						       old_to_newseq_map);
			}
		}
	}

	if (array_is_created(&t->keyword_resets)) {
		sort_appends_seq_range(&t->keyword_resets, t->first_new_seq,
				       old_to_newseq_map);
	}
}

void mail_index_transaction_sort_appends(struct mail_index_transaction *t)
{
	struct mail_index_record *recs, *sorted_recs;
	struct uid_map *new_uid_map;
	uint32_t *old_to_newseq_map;
	unsigned int i, count;

	if (!t->appends_nonsorted || !array_is_created(&t->appends))
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

	mail_index_transaction_sort_appends_ext(&t->ext_rec_updates,
						t->first_new_seq,
						old_to_newseq_map);
	mail_index_transaction_sort_appends_ext(&t->ext_rec_atomics,
						t->first_new_seq,
						old_to_newseq_map);
	mail_index_transaction_sort_appends_keywords(t, old_to_newseq_map);
	i_free(old_to_newseq_map);

	t->appends_nonsorted = FALSE;
}
