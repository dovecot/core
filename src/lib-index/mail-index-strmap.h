#ifndef MAIL_INDEX_STRMAP_H
#define MAIL_INDEX_STRMAP_H

#include "hash2.h"

struct mail_index;
struct mail_index_view;

struct mail_index_strmap_header {
#define MAIL_INDEX_STRMAP_VERSION 1
	uint8_t version;
	uint8_t unused[3];

	uint32_t uid_validity;
};

struct mail_index_strmap_rec {
	uint32_t uid;
	uint32_t ref_index;
	/* unique index number for the string */
	uint32_t str_idx;
};
ARRAY_DEFINE_TYPE(mail_index_strmap_rec, struct mail_index_strmap_rec);

typedef bool
mail_index_strmap_key_cmp_t(const char *key,
			    const struct mail_index_strmap_rec *rec,
			    void *context);
/* Returns 1 if matches, 0 if not, -1 if one of the records is expunged and
   the result can't be determined */
typedef int
mail_index_strmap_rec_cmp_t(const struct mail_index_strmap_rec *rec1,
			    const struct mail_index_strmap_rec *rec2,
			    void *context);
/* called when string indexes are renumbered. idx_map[old_idx] = new_idx.
   if new_idx is 0, the record was expunged. As a special case if count=0,
   the strmap was reset. */
typedef void mail_index_strmap_remap_t(const uint32_t *idx_map,
				       unsigned int old_count,
				       unsigned int new_count, void *context);

struct mail_index_strmap *
mail_index_strmap_init(struct mail_index *index, const char *suffix);
void mail_index_strmap_deinit(struct mail_index_strmap **strmap);

/* Returns strmap records and hash that can be used for read-only access.
   The records array always teminates with a record containing zeros (but it's
   not counted in the array count). */
struct mail_index_strmap_view *
mail_index_strmap_view_open(struct mail_index_strmap *strmap,
			    struct mail_index_view *idx_view,
			    mail_index_strmap_key_cmp_t *key_compare_cb,
			    mail_index_strmap_rec_cmp_t *rec_compare_cb,
			    mail_index_strmap_remap_t *remap_cb,
			    void *context,
			    const ARRAY_TYPE(mail_index_strmap_rec) **recs_r,
			    const struct hash2_table **hash_r);
void mail_index_strmap_view_close(struct mail_index_strmap_view **view);

/* Return the highest used string index. */
uint32_t mail_index_strmap_view_get_highest_idx(struct mail_index_strmap_view *view);

/* Synchronize strmap: Caller adds missing entries, expunged messages may be
   removed internally and the changes are written to disk. Note that the strmap
   recs/hash shouldn't be used until _sync_commit() is called, because the
   string indexes may be renumbered if another process had already written the
   same changes as us. */
struct mail_index_strmap_view_sync *
mail_index_strmap_view_sync_init(struct mail_index_strmap_view *view,
				 uint32_t *last_uid_r);
void mail_index_strmap_view_sync_add(struct mail_index_strmap_view_sync *sync,
				     uint32_t uid, uint32_t ref_index,
				     const char *key);
void mail_index_strmap_view_sync_add_unique(struct mail_index_strmap_view_sync *sync,
					    uint32_t uid, uint32_t ref_index);
void mail_index_strmap_view_sync_commit(struct mail_index_strmap_view_sync **sync);
void mail_index_strmap_view_sync_rollback(struct mail_index_strmap_view_sync **sync);

#endif
