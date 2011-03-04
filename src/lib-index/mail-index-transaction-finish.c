/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-index-transaction-private.h"

int mail_transaction_expunge_guid_cmp(const struct mail_transaction_expunge_guid *e1,
				      const struct mail_transaction_expunge_guid *e2)
{
	if (e1->uid < e2->uid)
		return -1;
	else if (e1->uid > e2->uid)
		return 1;
	else
		return 0;
}

void mail_index_transaction_sort_expunges(struct mail_index_transaction *t)
{
	if (!t->expunges_nonsorted)
		return;

	array_sort(&t->expunges, mail_transaction_expunge_guid_cmp);
	t->expunges_nonsorted = FALSE;
}

static void
ext_reset_update_atomic(struct mail_index_transaction *t,
			uint32_t ext_id, uint32_t expected_reset_id)
{
	const struct mail_index_ext *map_ext;
	struct mail_transaction_ext_reset *reset;
	uint32_t idx, reset_id;

	if (!mail_index_map_get_ext_idx(t->view->index->map, ext_id, &idx)) {
		/* new extension */
		reset_id = 1;
	} else {
		map_ext = array_idx(&t->view->index->map->extensions, idx);
		reset_id = map_ext->reset_id + 1;
	}
	if (reset_id != expected_reset_id) {
		/* ignore this extension update */
		mail_index_ext_set_reset_id(t, ext_id, 0);
		return;
	}

	if (reset_id == 0)
		reset_id++;

	array_idx_set(&t->ext_reset_ids, ext_id, &reset_id);

	/* reseting existing data is optional */
	if (array_is_created(&t->ext_resets)) {
		reset = array_idx_modifiable(&t->ext_resets, ext_id);
		if (reset->new_reset_id == (uint32_t)-1)
			reset->new_reset_id = reset_id;
	}
}

static void
transaction_update_atomic_reset_ids(struct mail_index_transaction *t)
{
	const uint32_t *expected_reset_ids;
	unsigned int ext_id, count;

	if (!array_is_created(&t->ext_reset_atomic))
		return;

	expected_reset_ids = array_get(&t->ext_reset_atomic, &count);
	for (ext_id = 0; ext_id < count; ext_id++) {
		if (expected_reset_ids[ext_id] != 0) {
			ext_reset_update_atomic(t, ext_id,
						expected_reset_ids[ext_id]);
		}
	}
}

static unsigned int
mail_transaction_drop_range(struct mail_index_transaction *t,
			    struct mail_transaction_flag_update update,
			    unsigned int update_idx,
			    ARRAY_TYPE(seq_range) *keeps)
{
	const struct seq_range *keep_range;
	unsigned int i, keep_count;

	keep_range = array_get(keeps, &keep_count);
	if (keep_count == 1 &&
	    update.uid1 == keep_range[0].seq1 &&
	    update.uid2 == keep_range[0].seq2) {
		/* evereything is kept */
		return update_idx + 1;
	}

	array_delete(&t->updates, update_idx, 1);

	/* add back all the updates we want to keep */
	for (i = 0; i < keep_count; i++, update_idx++) {
		update.uid1 = keep_range[i].seq1;
		update.uid2 = keep_range[i].seq2;
		array_insert(&t->updates, update_idx, &update, 1);
	}
	return update_idx;
}

static void
mail_index_transaction_finish_flag_updates(struct mail_index_transaction *t)
{
	const struct mail_transaction_flag_update *updates, *u;
	const struct mail_index_record *rec;
	unsigned int i, count;
	ARRAY_TYPE(seq_range) keeps;
	uint32_t seq;

	if (!t->drop_unnecessary_flag_updates || !array_is_created(&t->updates))
		return;

	t_array_init(&keeps, 64);
	updates = array_get(&t->updates, &count);
	for (i = 0; i < count; ) {
		/* first get the list of changes to drop */
		u = &updates[i];
		array_clear(&keeps);
		for (seq = u->uid1; seq <= u->uid2; seq++) {
			rec = mail_index_lookup(t->view, seq);
			if ((rec->flags & u->add_flags) != u->add_flags ||
			    (rec->flags & u->remove_flags) != 0) {
				/* keep this change */
				seq_range_array_add(&keeps, 0, seq);
			}
		}
		i = mail_transaction_drop_range(t, updates[i], i, &keeps);
		updates = array_get(&t->updates, &count);
	}

	if (array_count(&t->updates) == 0)
		array_free(&t->updates);
}

static void
mail_index_transaction_check_conflicts(struct mail_index_transaction *t)
{
	uint32_t seq;
	bool ret1, ret2;

	i_assert(t->max_modseq != 0);
	i_assert(t->conflict_seqs != NULL);

	if (t->max_modseq == mail_index_modseq_get_highest(t->view)) {
		/* no conflicts possible */
		return;
	}
	if (t->min_flagupdate_seq == 0) {
		/* no flag updates */
		return;
	}

	for (seq = t->min_flagupdate_seq; seq <= t->max_flagupdate_seq; seq++) {
		if (mail_index_modseq_lookup(t->view, seq) > t->max_modseq) {
			ret1 = mail_index_cancel_flag_updates(t, seq);
			ret2 = mail_index_cancel_keyword_updates(t, seq);
			if (ret1 || ret2)
				seq_range_array_add(t->conflict_seqs, 0, seq);
		}
	}
	mail_index_transaction_set_log_updates(t);
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
        struct mail_index_transaction_keyword_update *update;

	if (!array_is_created(&t->keyword_updates))
		return;

	array_foreach_modifiable(&t->keyword_updates, update) {
		mail_index_convert_to_uid_ranges(t, &update->add_seq);
		mail_index_convert_to_uid_ranges(t, &update->remove_seq);
	}
}

static void expunges_convert_to_uids(struct mail_index_transaction *t)
{
	struct mail_transaction_expunge_guid *expunges;
	unsigned int src, dest, count;

	if (!array_is_created(&t->expunges))
		return;

	mail_index_transaction_sort_expunges(t);

	expunges = array_get_modifiable(&t->expunges, &count);
	if (count == 0)
		return;

	/* convert uids and drop duplicates */
	expunges[0].uid = mail_index_transaction_get_uid(t, expunges[0].uid);
	for (src = dest = 1; src < count; src++) {
		expunges[dest].uid =
			mail_index_transaction_get_uid(t, expunges[src].uid);
		if (expunges[dest-1].uid != expunges[dest].uid) {
			memcpy(expunges[dest].guid_128, expunges[src].guid_128,
			       sizeof(expunges[dest].guid_128));
			dest++;
		}
	}
	array_delete(&t->expunges, dest, count-dest);
}

static void
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *update;

	if (array_is_created(&t->ext_rec_updates)) {
		array_foreach_modifiable(&t->ext_rec_updates, update)
			mail_index_convert_to_uids(t, update);
	}
	if (array_is_created(&t->ext_rec_atomics)) {
		array_foreach_modifiable(&t->ext_rec_atomics, update)
			mail_index_convert_to_uids(t, update);
	}

        keyword_updates_convert_to_uids(t);
	expunges_convert_to_uids(t);
	mail_index_convert_to_uids(t, (void *)&t->modseq_updates);
	mail_index_convert_to_uid_ranges(t, (void *)&t->updates);
	mail_index_convert_to_uid_ranges(t, &t->keyword_resets);
}

void mail_index_transaction_finish(struct mail_index_transaction *t)
{
	if (array_is_created(&t->appends)) {
		mail_index_update_day_headers(t);
		mail_index_transaction_sort_appends(t);
	}
	mail_index_transaction_finish_flag_updates(t);

	if (array_is_created(&t->ext_reset_atomic))
		transaction_update_atomic_reset_ids(t);
	if (t->max_modseq != 0)
		mail_index_transaction_check_conflicts(t);
	/* finally convert all sequences to UIDs before we write them,
	   but after we've checked and removed conflicts */
	mail_index_transaction_convert_to_uids(t);

	/* and kind of ugly way to update highest modseq */
	if (t->min_highest_modseq != 0)
		mail_index_update_modseq(t, 0, t->min_highest_modseq);
}
