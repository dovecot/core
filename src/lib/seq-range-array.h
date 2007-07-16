#ifndef __SEQ_RANGE_ARRAY_H
#define __SEQ_RANGE_ARRAY_H

struct seq_range {
	uint32_t seq1, seq2;
};

ARRAY_DEFINE_TYPE(seq_range, struct seq_range);

void seq_range_array_add(ARRAY_TYPE(seq_range) *array, unsigned int init_count,
			 uint32_t seq);
bool seq_range_array_remove(ARRAY_TYPE(seq_range) *array, uint32_t seq);
void seq_range_array_remove_range(ARRAY_TYPE(seq_range) *array,
				  uint32_t seq1, uint32_t seq2);
bool seq_range_exists(const ARRAY_TYPE(seq_range) *array, uint32_t seq);

#endif
