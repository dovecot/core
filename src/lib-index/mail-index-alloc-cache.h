#ifndef MAIL_INDEX_ALLOC_CACHE_H
#define MAIL_INDEX_ALLOC_CACHE_H

/* If using in-memory indexes, give index_dir=NULL. */
struct mail_index *
mail_index_alloc_cache_get(const char *mailbox_path,
			   const char *index_dir, const char *prefix);
void mail_index_alloc_cache_unref(struct mail_index **index);

void mail_index_alloc_cache_destroy_unrefed(void);

/* internal: */
void mail_index_alloc_cache_index_opened(struct mail_index *index);

#endif
