#ifndef SQUAT_UIDLIST_H
#define SQUAT_UIDLIST_H

struct squat_trie;
struct squat_uidlist_build_context;
struct squat_uidlist_rebuild_context;

struct squat_uidlist_file_header {
	uint32_t indexid;
	uint32_t used_file_size;
	uint32_t block_list_offset;
	uint32_t count, link_count;
};

/*
   uidlist file:

   struct uidlist_header;

   // size includes both prev_offset and uidlist
   packed (size << 2) | packed_flags; // UIDLIST_PACKED_FLAG_*
   [packed prev_offset;] // If UIDLIST_PACKED_FLAG_BEGINS_WITH_OFFSET is set
   if (UIDLIST_PACKED_FLAG_BITMASK) {
     packed base_uid; // first UID in uidlist
     uint8_t bitmask[]; // first bit is base_uid+1
   } else {
     // FIXME: packed range
   }
*/

#define UIDLIST_IS_SINGLETON(idx) \
	(((idx) & 1) != 0 || (idx) < (0x100 << 1))

struct squat_uidlist *squat_uidlist_init(struct squat_trie *trie);
void squat_uidlist_deinit(struct squat_uidlist *uidlist);

int squat_uidlist_refresh(struct squat_uidlist *uidlist);

int squat_uidlist_build_init(struct squat_uidlist *uidlist,
			     struct squat_uidlist_build_context **ctx_r);
uint32_t squat_uidlist_build_add_uid(struct squat_uidlist_build_context *ctx,
				     uint32_t uid_list_idx, uint32_t uid);
void squat_uidlist_build_flush(struct squat_uidlist_build_context *ctx);
int squat_uidlist_build_finish(struct squat_uidlist_build_context *ctx);
void squat_uidlist_build_deinit(struct squat_uidlist_build_context **ctx);

int squat_uidlist_rebuild_init(struct squat_uidlist_build_context *build_ctx,
			       bool compress,
			       struct squat_uidlist_rebuild_context **ctx_r);
uint32_t squat_uidlist_rebuild_next(struct squat_uidlist_rebuild_context *ctx,
				    const ARRAY_TYPE(uint32_t) *uids);
uint32_t squat_uidlist_rebuild_nextu(struct squat_uidlist_rebuild_context *ctx,
				     const ARRAY_TYPE(seq_range) *uids);
int squat_uidlist_rebuild_finish(struct squat_uidlist_rebuild_context *ctx,
				 bool cancel);

int squat_uidlist_get(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
		      ARRAY_TYPE(uint32_t) *uids);
uint32_t squat_uidlist_singleton_last_uid(uint32_t uid_list_idx);

int squat_uidlist_get_seqrange(struct squat_uidlist *uidlist,
			       uint32_t uid_list_idx,
			       ARRAY_TYPE(seq_range) *seq_range_arr);
int squat_uidlist_filter(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			 ARRAY_TYPE(seq_range) *uids);

void squat_uidlist_delete(struct squat_uidlist *uidlist);
size_t squat_uidlist_mem_used(struct squat_uidlist *uidlist,
			      unsigned int *count_r);

#endif
