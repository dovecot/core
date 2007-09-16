#ifndef SQUAT_UIDLIST_H
#define SQUAT_UIDLIST_H

#include "seq-range-array.h"

struct squat_trie;
struct squat_uidlist;

struct squat_uidlist *
squat_uidlist_init(struct squat_trie *trie, const char *path,
		   uint32_t uidvalidity, bool mmap_disable);
void squat_uidlist_deinit(struct squat_uidlist *uidlist);

/* Make sure that we've the latest uidlist file fully mapped. */
int squat_uidlist_refresh(struct squat_uidlist *uidlist);

/* Get the last UID added to the file. */
int squat_uidlist_get_last_uid(struct squat_uidlist *uidlist, uint32_t *uid_r);

/* Add new UID to given UID list. The uid_list_idx is updated to contain the
   new list index. It must be put through _finish_list() before it's actually
   written to disk. */
int squat_uidlist_add(struct squat_uidlist *uidlist, uint32_t *uid_list_idx,
		      uint32_t uid);
/* Write UID list into disk. The uid_list_idx is updated to contain the new
   permanent index for it. */
int squat_uidlist_finish_list(struct squat_uidlist *uidlist,
			      uint32_t *uid_list_idx);
int squat_uidlist_flush(struct squat_uidlist *uidlist, uint32_t uid_validity);
/* Returns TRUE if uidlist should be compressed. current_message_count can be
   (unsigned int)-1 if you don't want include it in the check. */
bool squat_uidlist_need_compress(struct squat_uidlist *uidlist,
				 unsigned int current_message_count);
/* Mark the uidlist containing expunged messages. update_disk=FALSE should be
   done when the uidlist is going to be compressed and this function only tells
   the compression to check for the expunged messages. */
int squat_uidlist_mark_having_expunges(struct squat_uidlist *uidlist,
				       bool update_disk);

/* Compress the uidlist file. existing_uids may be NULL if they're not known. */
struct squat_uidlist_compress_ctx *
squat_uidlist_compress_begin(struct squat_uidlist *uidlist,
			     const ARRAY_TYPE(seq_range) *existing_uids);
int squat_uidlist_compress_next(struct squat_uidlist_compress_ctx *ctx,
				uint32_t *uid_list_idx);
void squat_uidlist_compress_rollback(struct squat_uidlist_compress_ctx **ctx);
int squat_uidlist_compress_commit(struct squat_uidlist_compress_ctx **ctx);

/* Returns UIDs for a given UID list index. */
int squat_uidlist_get(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
		      ARRAY_TYPE(seq_range) *result);
/* Filter out UIDs which don't appear in the given UID list from the given
   result array */
int squat_uidlist_filter(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			 ARRAY_TYPE(seq_range) *result);

/* Returns TRUE when uidlist has used so much memory that it'd prefer to
   get flushed. */
bool squat_uidlist_want_flush(struct squat_uidlist *uidlist);

size_t squat_uidlist_mem_used(struct squat_uidlist *uidlist,
			      unsigned int *count_r);

#endif
