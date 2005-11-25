#ifndef __SEQ_RANGE_ARRAY_H
#define __SEQ_RANGE_ARRAY_H

struct seq_range {
	uint32_t seq1, seq2;
};

void seq_range_array_add(array_t *array, unsigned int init_count, uint32_t seq);
void seq_range_array_remove(array_t *array, uint32_t seq);
int seq_range_exists(array_t *array, uint32_t seq);

#endif
