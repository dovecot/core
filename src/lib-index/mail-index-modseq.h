#ifndef MAIL_INDEX_MODSEQ_H
#define MAIL_INDEX_MODSEQ_H

#include "mail-types.h"

#define MAIL_INDEX_MODSEQ_EXT_NAME "modseq"

struct mail_keywords;
struct mail_index;
struct mail_index_map;
struct mail_index_view;
struct mail_index_modseq;
struct mail_index_map_modseq;
struct mail_index_sync_map_ctx;
struct mail_index_modseq_sync;

void mail_index_modseq_init(struct mail_index *index);

/* Save a copy of the current modseq header to map->modseq_hdr_snapshot. This
   is expected to be called when reading the dovecot.index header before any
   changes are applied on top of it from dovecot.index.log. */
void mail_index_modseq_hdr_snapshot_update(struct mail_index_map *map);

const struct mail_index_modseq_header *
mail_index_map_get_modseq_header(struct mail_index_map *map);
uint64_t mail_index_map_modseq_get_highest(struct mail_index_map *map);
void mail_index_modseq_enable(struct mail_index *index);
bool mail_index_have_modseq_tracking(struct mail_index *index);
uint64_t mail_index_modseq_get_highest(struct mail_index_view *view);

uint64_t mail_index_modseq_lookup(struct mail_index_view *view, uint32_t seq);
int mail_index_modseq_set(struct mail_index_view *view,
			  uint32_t seq, uint64_t min_modseq);
void mail_index_modseq_update_to_highest(struct mail_index_modseq_sync *ctx,
					 uint32_t seq1, uint32_t seq2);

struct mail_index_modseq_sync *
mail_index_modseq_sync_begin(struct mail_index_sync_map_ctx *sync_map_ctx);
void mail_index_modseq_sync_end(struct mail_index_modseq_sync **ctx);

void mail_index_modseq_hdr_update(struct mail_index_modseq_sync *ctx);

bool mail_index_modseq_get_next_log_offset(struct mail_index_view *view,
					   uint64_t modseq, uint32_t *log_seq_r,
					   uoff_t *log_offset_r);

#endif
