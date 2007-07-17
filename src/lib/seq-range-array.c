/* Copyright (c) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"

static bool seq_range_lookup(const ARRAY_TYPE(seq_range) *array,
			     uint32_t seq, unsigned int *idx_r)
{
	const struct seq_range *data;
	unsigned int idx, left_idx, right_idx, count;

	data = array_get(array, &count);

	idx = 0; left_idx = 0; right_idx = count;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].seq1 <= seq) {
			if (data[idx].seq2 >= seq) {
				/* it's already in the range */
				*idx_r = idx;
				return TRUE;
			}
			left_idx = idx+1;
		} else {
			right_idx = idx;
		}
	}
	*idx_r = idx;
	return FALSE;
}

void seq_range_array_add(ARRAY_TYPE(seq_range) *array,
			 unsigned int init_count, uint32_t seq)
{
	struct seq_range *data, value;
	unsigned int idx, count;

	value.seq1 = value.seq2 = seq;

	if (!array_is_created(array))
		i_array_init(array, init_count);

	data = array_get_modifiable(array, &count);
	if (count == 0) {
		array_append(array, &value, 1);
		return;
	}

	/* quick checks */
	if (data[count-1].seq2 == seq-1) {
		/* grow last range */
		data[count-1].seq2 = seq;
		return;
	}
	if (data[count-1].seq2 < seq) {
		array_append(array, &value, 1);
		return;
	}
	if (data[0].seq1 == seq+1) {
		/* grow down first range */
		data[0].seq1 = seq;
		return;
	}
	if (data[0].seq1 > seq) {
		array_insert(array, 0, &value, 1);
		return;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	if (seq_range_lookup(array, seq, &idx))
		return;

	if (data[idx].seq2 < seq)
		idx++;

        /* idx == count couldn't happen because we already handle it above */
	i_assert(idx < count && data[idx].seq1 >= seq);
	i_assert(data[idx].seq1 > seq || data[idx].seq2 < seq);

	if (data[idx].seq1 == seq+1) {
		data[idx].seq1 = seq;
		if (idx > 0 && data[idx-1].seq2 == seq-1) {
			/* merge */
			data[idx-1].seq2 = data[idx].seq2;
			array_delete(array, idx, 1);
		}
	} else if (data[idx].seq2 == seq-1) {
		i_assert(idx+1 < count); /* already handled above */
		data[idx].seq2 = seq;
		if (data[idx+1].seq1 == seq+1) {
			/* merge */
			data[idx+1].seq1 = data[idx].seq1;
			array_delete(array, idx, 1);
		}
	} else {
		array_insert(array, idx, &value, 1);
	}
}

bool seq_range_array_remove(ARRAY_TYPE(seq_range) *array, uint32_t seq)
{
	struct seq_range *data, value;
	unsigned int idx, left_idx, right_idx, count;

	if (!array_is_created(array))
		return FALSE;

	data = array_get_modifiable(array, &count);
	if (count == 0)
		return FALSE;

	/* quick checks */
	if (seq > data[count-1].seq2 || seq < data[0].seq1) {
		/* outside the range */
		return FALSE;
	}
	if (data[count-1].seq2 == seq) {
		/* shrink last range */
		if (data[count-1].seq1 != data[count-1].seq2)
			data[count-1].seq2--;
		else
			array_delete(array, count-1, 1);
		return TRUE;
	}
	if (data[0].seq1 == seq) {
		/* shrink up first range */
		if (data[0].seq1 != data[0].seq2)
			data[0].seq1++;
		else
			array_delete(array, 0, 1);
		return TRUE;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	idx = 0; left_idx = 0; right_idx = count;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].seq1 > seq)
			right_idx = idx;
		else if (data[idx].seq2 < seq)
			left_idx = idx+1;
		else {
			/* found it */
			if (data[idx].seq1 == seq) {
				if (data[idx].seq1 == data[idx].seq2) {
					/* a single sequence range.
					   remove it entirely */
					array_delete(array, idx, 1);
				} else {
					/* shrink the range */
					data[idx].seq1++;
				}
			} else if (data[idx].seq2 == seq) {
				/* shrink the range */
				data[idx].seq2--;
			} else {
				/* split the sequence range */
				value.seq1 = seq + 1;
				value.seq2 = data[idx].seq2;
				data[idx].seq2 = seq - 1;

				array_insert(array, idx + 1, &value, 1);
			}
			return TRUE;
		}
	}
	return FALSE;
}

unsigned int seq_range_array_remove_range(ARRAY_TYPE(seq_range) *array,
					  uint32_t seq1, uint32_t seq2)
{
	const struct seq_range *data;
	unsigned int idx, idx2, count, remove_count = 0;

	/* remove first and last. this makes sure that everything between
	   can simply be deleted with array_delete().

	   FIXME: it would be faster if we did only one binary lookup here
	   and handled the splitting ourself.. */
	if (seq_range_array_remove(array, seq1++))
		remove_count++;
	if (seq1 > seq2)
		return remove_count;

	if (seq_range_array_remove(array, seq2--))
		remove_count++;
	if (seq1 == seq2)
		return remove_count;

	/* find the beginning */
	data = array_get(array, &count);
	(void)seq_range_lookup(array, seq1, &idx);
	if (idx < count && data[idx].seq2 < seq1)
		idx++;

	if (idx == count)
		return remove_count;

	i_assert(data[idx].seq1 >= seq1);
	for (idx2 = idx; idx2 < count; idx2++) {
		if (data[idx2].seq1 > seq2)
			break;
		remove_count += data[idx2].seq2 - data[idx2].seq1 + 1;
	}
	array_delete(array, idx, idx2-idx);
	return remove_count;
}

bool seq_range_exists(const ARRAY_TYPE(seq_range) *array, uint32_t seq)
{
	unsigned int idx;

	return seq_range_lookup(array, seq, &idx);
}
