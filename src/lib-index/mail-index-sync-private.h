#ifndef MAIL_INDEX_SYNC_PRIVATE_H
#define MAIL_INDEX_SYNC_PRIVATE_H

#include "mail-index-private.h"
#include "mail-transaction-log.h"

struct uid_range {
	uint32_t uid1, uid2;
};
ARRAY_DEFINE_TYPE(uid_range, struct uid_range);

struct mail_index_sync_list {
	const ARRAY_TYPE(uid_range) *array;
	unsigned int idx;
	unsigned int keyword_idx:31;
	unsigned int keyword_remove:1;
};

struct mail_index_expunge_handler {
	mail_index_expunge_handler_t *handler;
	void *context;
	void **sync_context;
	uint32_t record_offset;
};

struct mail_index_sync_map_ctx {
	struct mail_index_view *view;
	struct mail_index_modseq_sync *modseq_ctx;
	uint32_t cur_ext_map_idx;

	uint32_t ext_intro_seq;
	uoff_t ext_intro_offset, ext_intro_end_offset;

	ARRAY_DEFINE(expunge_handlers, struct mail_index_expunge_handler);
	ARRAY_DEFINE(extra_contexts, void *);
	buffer_t *unknown_extensions;

        enum mail_index_sync_handler_type type;

	unsigned int sync_handlers_initialized:1;
	unsigned int expunge_handlers_set:1;
	unsigned int expunge_handlers_used:1;
	unsigned int cur_ext_ignore:1;
	unsigned int internal_update:1; /* used by keywords for ext_intro */
	unsigned int errors:1;
};

extern struct mail_transaction_map_functions mail_index_map_sync_funcs;

void mail_index_sync_map_init(struct mail_index_sync_map_ctx *sync_map_ctx,
			      struct mail_index_view *view,
			      enum mail_index_sync_handler_type type);
void mail_index_sync_map_deinit(struct mail_index_sync_map_ctx *sync_map_ctx);
int mail_index_sync_map(struct mail_index_map **map,
			enum mail_index_sync_handler_type type, bool force);

int mail_index_sync_record(struct mail_index_sync_map_ctx *ctx,
			   const struct mail_transaction_header *hdr,
			   const void *data);

struct mail_index_map *
mail_index_sync_get_atomic_map(struct mail_index_sync_map_ctx *ctx);
void mail_index_sync_write_seq_update(struct mail_index_sync_map_ctx *ctx,
				      uint32_t seq1, uint32_t seq2);

void mail_index_sync_init_expunge_handlers(struct mail_index_sync_map_ctx *ctx);
void
mail_index_sync_deinit_expunge_handlers(struct mail_index_sync_map_ctx *ctx);
void mail_index_sync_init_handlers(struct mail_index_sync_map_ctx *ctx);
void mail_index_sync_deinit_handlers(struct mail_index_sync_map_ctx *ctx);

void mail_index_sync_ext_init(struct mail_index_sync_map_ctx *ctx,
			      const char *name, bool fix_size,
			      uint32_t *ext_map_idx_r);

int mail_index_sync_ext_intro(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_intro *u);
int mail_index_sync_ext_reset(struct mail_index_sync_map_ctx *ctx,
			      const struct mail_transaction_ext_reset *u);
int mail_index_sync_ext_hdr_update(struct mail_index_sync_map_ctx *ctx,
				   uint32_t offset, uint32_t size,
				   const void *data);
int
mail_index_sync_ext_rec_update(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_rec_update *u);
int
mail_index_sync_ext_atomic_inc(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_ext_atomic_inc *u);

int mail_index_sync_keywords(struct mail_index_sync_map_ctx *ctx,
			     const struct mail_transaction_header *hdr,
			     const struct mail_transaction_keyword_update *rec);
int
mail_index_sync_keywords_reset(struct mail_index_sync_map_ctx *ctx,
			       const struct mail_transaction_header *hdr,
			       const struct mail_transaction_keyword_reset *r);

void mail_index_sync_set_corrupted(struct mail_index_sync_map_ctx *ctx,
				   const char *fmt, ...) ATTR_FORMAT(2, 3);

#ifdef DEBUG
void mail_index_map_check(struct mail_index_map *map);
#endif

#endif
