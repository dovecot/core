/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"

static bool ATTR_NOWARN_UNUSED_RESULT
seq_range_lookup(const ARRAY_TYPE(seq_range) *array,
		 uint32_t seq, unsigned int *idx_r)
{
	const struct seq_range *data;
	unsigned int idx, left_idx, right_idx, count;

	data = array_get(array, &count);
	i_assert(count < INT_MAX);

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
	if (left_idx > idx)
		idx++;
	*idx_r = idx;
	return FALSE;
}

bool seq_range_array_add(ARRAY_TYPE(seq_range) *array, uint32_t seq)
{
	struct seq_range *data, value;
	unsigned int idx, count;

	value.seq1 = value.seq2 = seq;

	data = array_get_modifiable(array, &count);
	if (count == 0) {
		array_push_back(array, &value);
		return FALSE;
	}

	/* quick checks */
	if (data[count-1].seq2 < seq) {
		if (data[count-1].seq2 == seq-1) {
			/* grow last range */
			data[count-1].seq2 = seq;
		} else {
			array_push_back(array, &value);
		}
		return FALSE;
	}
	if (data[0].seq1 > seq) {
		if (data[0].seq1-1 == seq) {
			/* grow down first range */
			data[0].seq1 = seq;
		} else {
			array_push_front(array, &value);
		}
		return FALSE;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	if (seq_range_lookup(array, seq, &idx))
		return TRUE;

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
	} else {
		if (idx > 0 && data[idx-1].seq2 == seq-1)
			idx--;
		if (data[idx].seq2 == seq-1) {
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
	return FALSE;
}

void seq_range_array_add_with_init(ARRAY_TYPE(seq_range) *array,
				   unsigned int init_count, uint32_t seq)
{
	if (!array_is_created(array))
		i_array_init(array, init_count);
	seq_range_array_add(array, seq);
}

static void
seq_range_array_add_range_internal(ARRAY_TYPE(seq_range) *array,
				   uint32_t seq1, uint32_t seq2,
				   unsigned int *r_count)
{
	struct seq_range *data, value;
	unsigned int idx1, idx2, count;

	seq_range_lookup(array, seq1, &idx1);
	seq_range_lookup(array, seq2, &idx2);

	data = array_get_modifiable(array, &count);
	if (r_count != NULL) {
		/* Find number we're adding by counting the number we're
		   not adding, and subtracting that from the nominal range. */
		unsigned int added = seq2+1 - seq1;
		unsigned int countidx2 = idx2;
		unsigned int overcounted = 0u, notadded = 0u;
		unsigned int i;

		if (idx1 == count) {
			/* not in a range as too far right */
		} else if (seq1 < data[idx1].seq1) {
			/* not in a range, to the left of a real range */
		} else {
			/* count the whole of this range, which is an overcount */
			overcounted += seq1 - data[idx1].seq1;
			/* fencepost check: equality means the whole range is valid,
			   therefore there's no overcounting. Result = 0 overcount */
		}
		if (idx2 == count) {
			/* not in a range as too far right */
		} else  if (seq2 < data[idx2].seq1) {
			/* not in a range, to the left of a real range */
		} else {
			/* count the whole of this range, which is an overcount */
			overcounted += data[idx2].seq2 - seq2;
			countidx2++; /* may become == count i.e. past the end */
			/* fencepost check: equality  means the whole range is valid,
			   therefore there's no overcounting. Result = 0 overcount. */
		}
		/* Now count how many we're not adding */
		for (i = idx1; i < countidx2; i++)
			notadded += data[i].seq2+1 - data[i].seq1;
		/* Maybe the not added tally included some over-counting too */
		added -= (notadded - overcounted);
		*r_count = added;
	}

	if (idx1 > 0 && data[idx1-1].seq2+1 == seq1)
		idx1--;

	if (idx1 == idx2 &&
	    (idx2 == count || (seq2 < (uint32_t)-1 && data[idx2].seq1 > seq2+1)) &&
	    (idx1 == 0 || data[idx1-1].seq2 < seq1-1)) {
		/* no overlapping */
		value.seq1 = seq1;
		value.seq2 = seq2;
		array_insert(array, idx1, &value, 1);
	} else {
		i_assert(idx1 < count);
		if (seq1 < data[idx1].seq1)
			data[idx1].seq1 = seq1;
		if (seq2 > data[idx1].seq2) {
			/* merge */
			if (idx2 == count ||
			    data[idx2].seq1 > seq2+1)
				idx2--;
			if (seq2 >= data[idx2].seq2) {
				data[idx1].seq2 = seq2;
			} else {
				data[idx1].seq2 = data[idx2].seq2;
			}
			array_delete(array, idx1 + 1, idx2 - idx1);
		}
	}
}

void seq_range_array_add_range(ARRAY_TYPE(seq_range) *array,
			       uint32_t seq1, uint32_t seq2)
{
	seq_range_array_add_range_internal(array, seq1, seq2, NULL);
}
unsigned int seq_range_array_add_range_count(ARRAY_TYPE(seq_range) *array,
					     uint32_t seq1, uint32_t seq2)
{
	unsigned int count;
	seq_range_array_add_range_internal(array, seq1, seq2, &count);
	return count;
}

void seq_range_array_merge(ARRAY_TYPE(seq_range) *dest,
			   const ARRAY_TYPE(seq_range) *src)
{
	const struct seq_range *range;

	if (array_count(dest) == 0) {
		array_append_array(dest, src);
		return;
	}

	array_foreach(src, range)
		seq_range_array_add_range(dest, range->seq1, range->seq2);
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
			array_pop_front(array);
		return TRUE;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	i_assert(count < INT_MAX);
	left_idx = 0; right_idx = count;
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
	if (seq_range_array_remove(array, seq1))
		remove_count++;
	if (seq1 == seq2)
		return remove_count;
	seq1++;

	if (seq_range_array_remove(array, seq2--))
		remove_count++;
	if (seq1 > seq2)
		return remove_count;

	/* find the beginning */
	data = array_get(array, &count);
	seq_range_lookup(array, seq1, &idx);

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

unsigned int seq_range_array_remove_seq_range(ARRAY_TYPE(seq_range) *dest,
					      const ARRAY_TYPE(seq_range) *src)
{
	unsigned int ret = 0;
	const struct seq_range *src_range;

	array_foreach(src, src_range) {
		ret += seq_range_array_remove_range(dest, src_range->seq1,
						    src_range->seq2);
	}
	return ret;
}

void seq_range_array_remove_nth(ARRAY_TYPE(seq_range) *array,
				uint32_t n, uint32_t count)
{
	struct seq_range_iter iter;
	uint32_t seq1, seq2;

	if (count == 0)
		return;

	seq_range_array_iter_init(&iter, array);
	if (!seq_range_array_iter_nth(&iter, n, &seq1)) {
		/* n points beyond array */
		return;
	}
	if (count-1 >= (uint32_t)-1 - n ||
	    !seq_range_array_iter_nth(&iter, n + (count-1), &seq2)) {
		/* count points beyond array */
		seq2 = (uint32_t)-1;
	}
	seq_range_array_remove_range(array, seq1, seq2);
}

unsigned int seq_range_array_intersect(ARRAY_TYPE(seq_range) *dest,
				       const ARRAY_TYPE(seq_range) *src)
{
	const struct seq_range *src_range;
	unsigned int i, count, ret = 0;
	uint32_t last_seq = 0;

	src_range = array_get(src, &count);
	for (i = 0; i < count; i++) {
		if (last_seq + 1 < src_range[i].seq1) {
			ret += seq_range_array_remove_range(dest,
					last_seq + 1, src_range[i].seq1 - 1);
		}
		last_seq = src_range[i].seq2;
	}
	if (last_seq != (uint32_t)-1) {
		ret += seq_range_array_remove_range(dest, last_seq + 1,
						    (uint32_t)-1);
	}
	return ret;
}

bool seq_range_exists(const ARRAY_TYPE(seq_range) *array, uint32_t seq)
{
	unsigned int idx;

	return seq_range_lookup(array, seq, &idx);
}

bool seq_range_array_have_common(const ARRAY_TYPE(seq_range) *array1,
				 const ARRAY_TYPE(seq_range) *array2)
{
	const struct seq_range *range1, *range2;
	unsigned int i1, i2, count1, count2;

	range1 = array_get(array1, &count1);
	range2 = array_get(array2, &count2);
	for (i1 = i2 = 0; i1 < count1 && i2 < count2; ) {
		if (range1[i1].seq1 <= range2[i2].seq2 &&
		    range1[i1].seq2 >= range2[i2].seq1)
			return TRUE;

		if (range1[i1].seq1 < range2[i2].seq1)
			i1++;
		else
			i2++;
	}
	return FALSE;
}

unsigned int seq_range_count(const ARRAY_TYPE(seq_range) *array)
{
	const struct seq_range *range;
	unsigned int seq_count = 0;

	array_foreach(array, range)
		seq_count += range->seq2 - range->seq1 + 1;
	return seq_count;
}

void seq_range_array_invert(ARRAY_TYPE(seq_range) *array,
			    uint32_t min_seq, uint32_t max_seq)
{
	struct seq_range *range, value;
	unsigned int i, count;
	uint32_t prev_min_seq;

	if (array_is_created(array))
		range = array_get_modifiable(array, &count);
	else {
		range = NULL;
		count = 0;
	} 
	if (count == 0) {
		/* empty -> full */
		if (!array_is_created(array))
			i_array_init(array, 4);
		value.seq1 = min_seq;
		value.seq2 = max_seq;
		array_push_back(array, &value);
		return;
	}
	i_assert(range[0].seq1 >= min_seq);
	i_assert(range[count-1].seq2 <= max_seq);

	if (range[0].seq1 == min_seq && range[0].seq2 == max_seq) {
		/* full -> empty */
		array_clear(array);
		return;
	}

	for (i = 0; i < count; ) {
		prev_min_seq = min_seq;
		min_seq = range[i].seq2;
		if (range[i].seq1 == prev_min_seq) {
			array_delete(array, i, 1);
			range = array_get_modifiable(array, &count);
		} else {
			range[i].seq2 = range[i].seq1 - 1;
			range[i].seq1 = prev_min_seq;
			i++;
		}
		if (min_seq >= max_seq) {
			/* max_seq is reached. the rest of the array should be
			   empty. we'll return here, because min_seq++ may
			   wrap to 0. */
			i_assert(min_seq == max_seq);
			i_assert(i == count);
			return;
		}
		min_seq++;
	}
	if (min_seq <= max_seq) {
		value.seq1 = min_seq;
		value.seq2 = max_seq;
		array_push_back(array, &value);
	}
}

void seq_range_array_iter_init(struct seq_range_iter *iter_r,
			       const ARRAY_TYPE(seq_range) *array)
{
	i_zero(iter_r);
	iter_r->array = array;
}

bool seq_range_array_iter_nth(struct seq_range_iter *iter, unsigned int n,
			      uint32_t *seq_r)
{
	const struct seq_range *range;
	unsigned int i, count, diff;

	if (n < iter->prev_n) {
		/* iterating backwards, don't bother optimizing */
		iter->prev_n = 0;
		iter->prev_idx = 0;
	}

	range = array_get(iter->array, &count);
	for (i = iter->prev_idx; i < count; i++) {
		diff = range[i].seq2 - range[i].seq1;
		if (n <= iter->prev_n + diff) {
			i_assert(n >= iter->prev_n);
			*seq_r = range[i].seq1 + (n - iter->prev_n);
			iter->prev_idx = i;
			return TRUE;
		}
		iter->prev_n += diff + 1;
	}
	iter->prev_idx = i;
	return FALSE;
}
