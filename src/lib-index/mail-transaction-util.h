#ifndef __MAIL_TRANSACTION_UTIL_H
#define __MAIL_TRANSACTION_UTIL_H

struct mail_transaction_type_map {
	enum mail_transaction_type type;
	enum mail_index_sync_type sync_type;
	size_t record_size;
};
extern const struct mail_transaction_type_map mail_transaction_type_map[];

struct mail_transaction_map_functions {
	int (*expunge)(const struct mail_transaction_expunge *e, void *context);
	int (*append)(const struct mail_index_record *rec, void *context);
	int (*flag_update)(const struct mail_transaction_flag_update *u,
			   void *context);
	int (*cache_update)(const struct mail_transaction_cache_update *u,
			    void *context);
};

const struct mail_transaction_type_map *
mail_transaction_type_lookup(enum mail_transaction_type type);
enum mail_transaction_type
mail_transaction_type_mask_get(enum mail_index_sync_type sync_type);

int mail_transaction_map(const struct mail_transaction_header *hdr,
			 const void *data,
			 struct mail_transaction_map_functions *map,
			 void *context);

void
mail_transaction_log_sort_expunges(buffer_t *expunges_buf,
				   const struct mail_transaction_expunge *src,
				   size_t src_buf_size);

/* Iterate through expunges buffer. iter_seek()'s seq1/seq2 is assumed to be
   in post-expunge view, iter_get() updates them to pre-expunge view. Some
   post-expunge sequence arrays may go through expunges, we split them so it
   won't be visible. */
struct mail_transaction_expunge_iter_ctx *
mail_transaction_expunge_iter_init(const buffer_t *expunges_buf);
void mail_transaction_expunge_iter_deinit(
	struct mail_transaction_expunge_iter_ctx *ctx);
/* Returns TRUE if seq1 or seq2 will be modified by iter_get(). If FALSE is
   returned calling iter_get() is a bit pointless. */
int mail_transaction_expunge_iter_seek(
	struct mail_transaction_expunge_iter_ctx *ctx,
	uint32_t seq1, uint32_t seq2);
/* Returns TRUE while sequences are returned. */
int mail_transaction_expunge_iter_get(
	struct mail_transaction_expunge_iter_ctx *ctx,
	uint32_t *seq1_r, uint32_t *seq2_r);

#endif
