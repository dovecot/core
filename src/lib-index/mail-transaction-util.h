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

#endif
