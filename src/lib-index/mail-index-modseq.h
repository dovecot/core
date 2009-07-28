#ifndef MAIL_INDEX_MODSEQ_H
#define MAIL_INDEX_MODSEQ_H

#define MAIL_INDEX_MODSEQ_EXT_NAME "modseq"

enum mail_flags;
struct mail_keywords;
struct mail_index;
struct mail_index_map;
struct mail_index_view;
struct mail_index_modseq;
struct mail_index_map_modseq;
struct mail_index_sync_map_ctx;

struct mail_index_modseq_header {
	/* highest used modseq */
	uint64_t highest_modseq;
	/* last tracked log file position */
	uint32_t log_seq;
	uint32_t log_offset;
};

void mail_index_modseq_init(struct mail_index *index);

const struct mail_index_modseq_header *
mail_index_map_get_modseq_header(struct mail_index_map *map);
uint64_t mail_index_map_modseq_get_highest(struct mail_index_map *map);
void mail_index_modseq_enable(struct mail_index *index);
uint64_t mail_index_modseq_get_highest(struct mail_index_view *view);

uint64_t mail_index_modseq_lookup(struct mail_index_view *view, uint32_t seq);
uint64_t mail_index_modseq_lookup_flags(struct mail_index_view *view,
					enum mail_flags flags_mask,
					uint32_t seq);
uint64_t mail_index_modseq_lookup_keywords(struct mail_index_view *view,
					   const struct mail_keywords *keywords,
					   uint32_t seq);
int mail_index_modseq_set(struct mail_index_view *view,
			  uint32_t seq, uint64_t min_modseq);

struct mail_index_modseq_sync *
mail_index_modseq_sync_begin(struct mail_index_sync_map_ctx *sync_map_ctx);
void mail_index_modseq_sync_end(struct mail_index_modseq_sync **ctx);

void mail_index_modseq_sync_map_replaced(struct mail_index_modseq_sync *ctx);
void mail_index_modseq_hdr_update(struct mail_index_modseq_sync *ctx);
void mail_index_modseq_append(struct mail_index_modseq_sync *ctx, uint32_t seq);
void mail_index_modseq_expunge(struct mail_index_modseq_sync *ctx,
			       uint32_t seq1, uint32_t seq2);
void mail_index_modseq_update_flags(struct mail_index_modseq_sync *ctx,
				    enum mail_flags flags_mask,
				    uint32_t seq1, uint32_t seq2);
void mail_index_modseq_update_keyword(struct mail_index_modseq_sync *ctx,
				      unsigned int keyword_idx,
				      uint32_t seq1, uint32_t seq2);
void mail_index_modseq_reset_keywords(struct mail_index_modseq_sync *ctx,
				      uint32_t seq1, uint32_t seq2);
void mail_index_modseq_update_highest(struct mail_index_modseq_sync *ctx,
				      uint64_t highest_modseq);

struct mail_index_map_modseq *
mail_index_map_modseq_clone(const struct mail_index_map_modseq *mmap);
void mail_index_map_modseq_free(struct mail_index_map_modseq **mmap);

bool mail_index_modseq_get_next_log_offset(struct mail_index_view *view,
					   uint64_t modseq, uint32_t *log_seq_r,
					   uoff_t *log_offset_r);

#endif
