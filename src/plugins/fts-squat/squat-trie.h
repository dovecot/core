#ifndef __SQUAT_TRIE_H
#define __SQUAT_TRIE_H

#include "seq-range-array.h"

struct squat_trie *squat_trie_open(const char *path);
void squat_trie_close(struct squat_trie *trie);

int squat_trie_add(struct squat_trie *trie, uint32_t uid,
		   const void *data, size_t size);
int squat_trie_flush(struct squat_trie *trie);
int squat_trie_compress(struct squat_trie *trie,
			const ARRAY_TYPE(seq_range) *existing_uids);

int squat_trie_mark_having_expunges(struct squat_trie *trie,
				    const ARRAY_TYPE(seq_range) *existing_uids,
				    unsigned int current_message_count);

int squat_trie_lookup(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
		      const char *str);
int squat_trie_filter(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
		      const char *str);

size_t squat_trie_mem_used(struct squat_trie *trie, unsigned int *count_r);

struct squat_uidlist *_squat_trie_get_uidlist(struct squat_trie *trie);

void _squat_trie_pack_num(buffer_t *buffer, uint32_t num);
uint32_t _squat_trie_unpack_num(const uint8_t **p, const uint8_t *end);

void squat_trie_set_corrupted(struct squat_trie *trie, const char *reason);

#endif
