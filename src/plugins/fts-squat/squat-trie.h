#ifndef SQUAT_TRIE_H
#define SQUAT_TRIE_H

#include "file-lock.h"
#include "seq-range-array.h"

struct squat_trie *
squat_trie_open(const char *path, uint32_t uidvalidity,
		enum file_lock_method lock_method, bool mmap_disable);
void squat_trie_close(struct squat_trie *trie);

int squat_trie_get_last_uid(struct squat_trie *trie, uint32_t *last_uid_r);

int squat_trie_lock(struct squat_trie *trie, int lock_type);
void squat_trie_unlock(struct squat_trie *trie);

struct squat_trie_build_context *
squat_trie_build_init(struct squat_trie *trie, uint32_t *last_uid_r);
int squat_trie_build_more(struct squat_trie_build_context *ctx, uint32_t uid,
			  const unsigned char *data, size_t size);
int squat_trie_build_deinit(struct squat_trie_build_context *ctx);

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

struct squat_uidlist *squat_trie_get_uidlist(struct squat_trie *trie);

void squat_trie_pack_num(buffer_t *buffer, uint32_t num);
uint32_t squat_trie_unpack_num(const uint8_t **p, const uint8_t *end);

void squat_trie_set_corrupted(struct squat_trie *trie, const char *reason);

#endif
