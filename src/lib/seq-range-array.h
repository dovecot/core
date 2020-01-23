#ifndef SEQ_RANGE_ARRAY_H
#define SEQ_RANGE_ARRAY_H

struct seq_range {
	uint32_t seq1, seq2;
};
ARRAY_DEFINE_TYPE(seq_range, struct seq_range);

struct seq_range_iter {
	const ARRAY_TYPE(seq_range) *array;
	unsigned int prev_n, prev_idx;
};

static inline uint32_t ATTR_PURE seq_range_length(struct seq_range *range)
{
	i_assert(range->seq2 >= range->seq1);
	return range->seq2 - range->seq1 + 1;
}

/* Add sequence to range. If the array isn't created yet, create it with
   initial size of init_count. */
bool ATTR_NOWARN_UNUSED_RESULT
seq_range_array_add(ARRAY_TYPE(seq_range) *array, uint32_t seq);
/* Like seq_range_array_add(), but if the array isn't already initialized do
   it with i_array_init(). */
void seq_range_array_add_with_init(ARRAY_TYPE(seq_range) *array,
				   unsigned int init_count, uint32_t seq);
void seq_range_array_add_range(ARRAY_TYPE(seq_range) *array,
			       uint32_t seq1, uint32_t seq2);
unsigned int seq_range_array_add_range_count(ARRAY_TYPE(seq_range) *array,
					     uint32_t seq1, uint32_t seq2);
void seq_range_array_merge(ARRAY_TYPE(seq_range) *dest,
			   const ARRAY_TYPE(seq_range) *src);
/* Merge the first n sequences from src into dest. */
void seq_range_array_merge_n(ARRAY_TYPE(seq_range) *dest,
			     const ARRAY_TYPE(seq_range) *src,
			     unsigned int count);
/* Remove the given sequence from range. Returns TRUE if it was found. */
bool ATTR_NOWARN_UNUSED_RESULT
seq_range_array_remove(ARRAY_TYPE(seq_range) *array, uint32_t seq);
/* Remove a sequence range. Returns number of sequences actually removed. */
unsigned int ATTR_NOWARN_UNUSED_RESULT
seq_range_array_remove_range(ARRAY_TYPE(seq_range) *array,
			     uint32_t seq1, uint32_t seq2);
unsigned int ATTR_NOWARN_UNUSED_RESULT
seq_range_array_remove_seq_range(ARRAY_TYPE(seq_range) *dest,
				 const ARRAY_TYPE(seq_range) *src);
/* Remove count number of sequences from the nth sequence (0 = first). */
void seq_range_array_remove_nth(ARRAY_TYPE(seq_range) *array,
				uint32_t n, uint32_t count);
/* Remove sequences from dest that don't exist in src. */
unsigned int ATTR_NOWARN_UNUSED_RESULT
seq_range_array_intersect(ARRAY_TYPE(seq_range) *dest,
			  const ARRAY_TYPE(seq_range) *src);
/* Returns TRUE if sequence exists in the range. */
bool seq_range_exists(const ARRAY_TYPE(seq_range) *array,
		      uint32_t seq) ATTR_PURE;
/* Returns TRUE if arrays have common sequences. */
bool seq_range_array_have_common(const ARRAY_TYPE(seq_range) *array1,
				 const ARRAY_TYPE(seq_range) *array2) ATTR_PURE;
/* Return number of sequences in the range. */
unsigned int seq_range_count(const ARRAY_TYPE(seq_range) *array) ATTR_PURE;

/* Invert the sequence range. For example 5:6 -> min_seq:4,7:max_seq.
   The array must not have any sequences outside min_seq..max_seq or this
   function will assert-crash. */
void seq_range_array_invert(ARRAY_TYPE(seq_range) *array,
			    uint32_t min_seq, uint32_t max_seq);

void seq_range_array_iter_init(struct seq_range_iter *iter_r,
			       const ARRAY_TYPE(seq_range) *array);
/* Get the nth sequence (0 = first). Returns FALSE if idx is too large. */
bool seq_range_array_iter_nth(struct seq_range_iter *iter, unsigned int n,
			      uint32_t *seq_r);

#endif
