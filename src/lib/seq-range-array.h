#ifndef SEQ_RANGE_ARRAY_H
#define SEQ_RANGE_ARRAY_H

struct seq_range {
	uint32_t seq1, seq2;
};

ARRAY_DEFINE_TYPE(seq_range, struct seq_range);

/* Add sequrence to range. If the array isn't created yet, create it with
   initial size of init_count. */
void seq_range_array_add(ARRAY_TYPE(seq_range) *array, unsigned int init_count,
			 uint32_t seq);
/* Remove given sequrence from range. Returns TRUE if it was found. */
bool seq_range_array_remove(ARRAY_TYPE(seq_range) *array, uint32_t seq);
/* Remove a sequence range. Returns number of sequences actually removed. */
unsigned int seq_range_array_remove_range(ARRAY_TYPE(seq_range) *array,
					  uint32_t seq1, uint32_t seq2);
/* Returns TRUE if sequence exists in the range. */
bool seq_range_exists(const ARRAY_TYPE(seq_range) *array, uint32_t seq);

/* Invert the sequence range. For example 5:6 -> min_seq:4,7:max_seq. */
void seq_range_array_invert(ARRAY_TYPE(seq_range) *array,
			    uint32_t min_seq, uint32_t max_seq);

#endif
