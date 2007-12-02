#ifndef SQUAT_TRIE_H
#define SQUAT_TRIE_H

#include "file-lock.h"
#include "seq-range-array.h"

enum squat_index_type {
	SQUAT_INDEX_TYPE_HEADER	= 0x01,
	SQUAT_INDEX_TYPE_BODY	= 0x02
};

struct squat_trie_build_context;

struct squat_trie *
squat_trie_init(const char *path, uint32_t uidvalidity,
		enum file_lock_method lock_method, bool mmap_disable);
void squat_trie_deinit(struct squat_trie **trie);

void squat_trie_refresh(struct squat_trie *trie);

int squat_trie_build_init(struct squat_trie *trie, uint32_t *last_uid_r,
			  struct squat_trie_build_context **ctx_r);
/* headers must be added before bodies */
int squat_trie_build_more(struct squat_trie_build_context *ctx,
			  uint32_t uid, enum squat_index_type type,
			  const unsigned char *data, unsigned int size);
int squat_trie_build_deinit(struct squat_trie_build_context **ctx);

int squat_trie_get_last_uid(struct squat_trie *trie, uint32_t *last_uid_r);
/* type specifies if we're looking at header, body or both */
int squat_trie_lookup(struct squat_trie *trie, const char *str,
		      enum squat_index_type type,
		      ARRAY_TYPE(seq_range) *definite_uids,
		      ARRAY_TYPE(seq_range) *maybe_uids);

struct squat_uidlist *squat_trie_get_uidlist(struct squat_trie *trie);
size_t squat_trie_mem_used(struct squat_trie *trie, unsigned int *count_r);

#endif
