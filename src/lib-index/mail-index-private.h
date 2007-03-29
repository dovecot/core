#ifndef __MAIL_INDEX_PRIVATE_H
#define __MAIL_INDEX_PRIVATE_H

#include "file-lock.h"
#include "mail-index.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"

struct mail_transaction_header;
struct mail_transaction_log_view;
struct mail_index_sync_map_ctx;

/* How many seconds to wait a lock for index file. */
#define MAIL_INDEX_LOCK_SECS 120
/* Index file is grown exponentially when we're adding less than this many
   records. */
#define MAIL_INDEX_MAX_POWER_GROW (1024*1024 / sizeof(struct mail_index_record))
/* How many times to retry opening index files if read/fstat returns ESTALE.
   This happens with NFS when the file has been deleted (ie. index file was
   rewritten by another computer than us). */
#define MAIL_INDEX_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT

#define MAIL_INDEX_IS_IN_MEMORY(index) \
	((index)->dir == NULL)

#define MAIL_INDEX_MAP_IS_IN_MEMORY(map) \
	((map)->buffer != NULL)

#define MAIL_INDEX_MAP_IDX(map, idx) \
	((struct mail_index_record *) \
		PTR_OFFSET((map)->records, (idx) * (map)->hdr.record_size))

typedef int mail_index_expunge_handler_t(struct mail_index_sync_map_ctx *ctx,
					 uint32_t seq, const void *data,
					 void **sync_context, void *context);
typedef int mail_index_sync_handler_t(struct mail_index_sync_map_ctx *ctx,
				      uint32_t seq, void *old_data,
				      const void *new_data, void **context);
typedef void mail_index_sync_lost_handler_t(struct mail_index *index);

ARRAY_DEFINE_TYPE(seq_array, uint32_t);

#define MAIL_INDEX_HEADER_SIZE_ALIGN(size) \
	(((size) + 7) & ~7)

struct mail_index_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t reset_id;
	uint32_t hdr_offset; /* points to mail_index_ext_header.data[] */
	uint32_t hdr_size; /* size of mail_index_ext_header.data[] */
	uint16_t record_offset;
	uint16_t record_size;
	uint16_t record_align;
};

struct mail_index_ext_header {
	uint32_t hdr_size; /* size of data[] */
	uint32_t reset_id;
	uint16_t record_offset;
	uint16_t record_size;
	uint16_t record_align;
	uint16_t name_size;
	/* unsigned char name[name_size] */
	/* unsigned char data[hdr_size] (starting 64bit aligned) */
};

struct mail_index_keyword_header {
	uint32_t keywords_count;
	/* struct mail_index_keyword_header_rec[] */
	/* char name[][] */
};

struct mail_index_keyword_header_rec {
	uint32_t unused; /* for backwards compatibility */
	uint32_t name_offset; /* relative to beginning of name[] */
};

enum mail_index_sync_handler_type {
	MAIL_INDEX_SYNC_HANDLER_FILE	= 0x01,
	MAIL_INDEX_SYNC_HANDLER_HEAD	= 0x02,
	MAIL_INDEX_SYNC_HANDLER_VIEW	= 0x04
};

struct mail_index_sync_handler {
	mail_index_sync_handler_t *callback;
        enum mail_index_sync_handler_type type;
};

struct mail_index_registered_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t hdr_size; /* size of mail_index_ext_header.data[] */
	uint16_t record_size;
	uint16_t record_align;

	struct mail_index_sync_handler sync_handler;
	mail_index_expunge_handler_t *expunge_handler;

	void *expunge_context;
	unsigned int expunge_handler_call_always:1;
};

struct mail_index_map {
	int refcount;

	struct mail_index_header hdr;
	const void *hdr_base;
	void *records; /* struct mail_index_record[] */
	unsigned int records_count;

	pool_t extension_pool;
	ARRAY_DEFINE(extensions, struct mail_index_ext);
	ARRAY_DEFINE(ext_id_map, uint32_t); /* index -> file */

	void *mmap_base;
	size_t mmap_size, mmap_used_size;

	buffer_t *buffer;
	buffer_t *hdr_copy_buf;

	ARRAY_DEFINE(keyword_idx_map, unsigned int); /* file -> index */

	/* If write_to_disk=TRUE and write_atomic=FALSE, these sequences
	   specify the range that needs to be written. Header should always
	   be rewritten. */
	uint32_t write_seq_first, write_seq_last;

	unsigned int keywords_read:1;
	unsigned int write_to_disk:1;
	unsigned int write_atomic:1; /* copy to new file and rename() */
};

struct mail_index_module_register {
	unsigned int id;
};

union mail_index_module_context {
	struct mail_index_module_register *reg;
};

struct mail_index {
	char *dir, *prefix;

	struct mail_cache *cache;
	struct mail_transaction_log *log;

	mode_t mode;
	gid_t gid;

	pool_t extension_pool;
	ARRAY_DEFINE(extensions, struct mail_index_registered_ext);

	ARRAY_DEFINE(sync_lost_handlers, mail_index_sync_lost_handler_t *);

	char *filepath;
	int fd;

        struct mail_index_map *map;
	const struct mail_index_header *hdr;
	uint32_t indexid;

	int lock_type, shared_lock_count, excl_lock_count;
	unsigned int lock_id;
	char *copy_lock_path;
	enum file_lock_method lock_method;

	struct file_lock *file_lock;
	struct dotlock *dotlock;

	/* These are typically same as map->hdr->log_file_*, but with
	   mmap_disable we may have synced more than index */
	uint32_t sync_log_file_seq;
	uoff_t sync_log_file_offset;

	pool_t keywords_pool;
	ARRAY_TYPE(keywords) keywords;
	struct hash_table *keywords_hash; /* name -> idx */

	uint32_t keywords_ext_id;
	unsigned int last_grow_count;

	/* Module-specific contexts. */
	ARRAY_DEFINE(module_contexts, union mail_index_module_context *);

	char *error;
	unsigned int nodiskspace:1;
	unsigned int index_lock_timeout:1;

	unsigned int opened:1;
	unsigned int log_locked:1;
	unsigned int mmap_disable:1;
	unsigned int fsync_disable:1;
	unsigned int mmap_no_write:1;
	unsigned int use_excl_dotlocks:1;
	unsigned int readonly:1;
	unsigned int fsck:1;
	unsigned int sync_update:1;
	unsigned int mapping:1;
};

extern struct mail_index_module_register mail_index_module_register;

/* Add/replace sync handler for specified extra record. */
void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id, bool call_always,
					 mail_index_expunge_handler_t *callback,
					 void *context);
void mail_index_unregister_expunge_handler(struct mail_index *index,
					   uint32_t ext_id);
void mail_index_register_sync_handler(struct mail_index *index, uint32_t ext_id,
				      mail_index_sync_handler_t *cb,
				      enum mail_index_sync_handler_type type);
void mail_index_unregister_sync_handler(struct mail_index *index,
					uint32_t ext_id);
void mail_index_register_sync_lost_handler(struct mail_index *index,
					   mail_index_sync_lost_handler_t *cb);
void mail_index_unregister_sync_lost_handler(struct mail_index *index,
					mail_index_sync_lost_handler_t *cb);

int mail_index_write_base_header(struct mail_index *index,
				 const struct mail_index_header *hdr);

int mail_index_reopen(struct mail_index *index, int fd);
int mail_index_create_tmp_file(struct mail_index *index, const char **path_r);

/* Returns 0 = ok, -1 = error. If update_index is TRUE, reopens the index
   file if needed to get later version of it (not necessarily latest due to
   races, unless transaction log is exclusively locked). */
int mail_index_lock_shared(struct mail_index *index, bool update_index,
			   unsigned int *lock_id_r);
/* Returns 0 = ok, -1 = error. */
int mail_index_lock_exclusive(struct mail_index *index,
			      unsigned int *lock_id_r);
void mail_index_unlock(struct mail_index *index, unsigned int lock_id);
/* Returns TRUE if given lock_id is valid. */
bool mail_index_is_locked(struct mail_index *index, unsigned int lock_id);

int mail_index_lock_fd(struct mail_index *index, const char *path, int fd,
		       int lock_type, unsigned int timeout_secs,
		       struct file_lock **lock_r);

/* Reopen index file if it has changed. */
int mail_index_reopen_if_needed(struct mail_index *index);

/* Map index file to memory, replacing the previous mapping for index.
   Returns 1 = ok, 0 = corrupted, -1 = error. If index needs fscking, it
   returns 1 but sets index->fsck = TRUE. */
int mail_index_map(struct mail_index *index, bool force);
/* Read the latest available header. Normally this is pretty much the same as
   calling mail_index_map(), but with mmap_disable the header can be generated
   by reading just log files, so eg. log_file_*_offset values can be wrong.
   Returns 1 = ok, 0 = EOF, -1 = error. */
int mail_index_get_latest_header(struct mail_index *index,
				 struct mail_index_header *hdr_r);
/* Unreference given mapping and unmap it if it's dropped to zero. */
void mail_index_unmap(struct mail_index *index, struct mail_index_map **map);
struct mail_index_map *
mail_index_map_clone(const struct mail_index_map *map,
		     uint32_t new_record_size);

uint32_t mail_index_map_lookup_ext(struct mail_index_map *map,
				   const char *name);
uint32_t
mail_index_map_register_ext(struct mail_index *index,
			    struct mail_index_map *map, const char *name,
			    uint32_t hdr_offset, uint32_t hdr_size,
			    uint32_t record_offset, uint32_t record_size,
			    uint32_t record_align, uint32_t reset_id);
int mail_index_map_get_ext_idx(struct mail_index_map *map,
			       uint32_t ext_id, uint32_t *idx_r);
const struct mail_index_ext *
mail_index_view_get_ext(struct mail_index_view *view, uint32_t ext_id);
void mail_index_view_recalc_counters(struct mail_index_view *view);

int mail_index_map_parse_keywords(struct mail_index *index,
                                  struct mail_index_map *map);

int mail_index_fix_header(struct mail_index *index, struct mail_index_map *map,
			  struct mail_index_header *hdr, const char **error_r);
bool mail_index_is_ext_synced(struct mail_transaction_log_view *log_view,
			      struct mail_index_map *map);

void mail_index_view_transaction_ref(struct mail_index_view *view);
void mail_index_view_transaction_unref(struct mail_index_view *view);

void mail_index_set_inconsistent(struct mail_index *index);

int mail_index_set_error(struct mail_index *index, const char *fmt, ...)
	__attr_format__(2, 3);
/* "%s failed with index file %s: %m" */
int mail_index_set_syscall_error(struct mail_index *index,
				 const char *function);
/* "%s failed with file %s: %m" */
int mail_index_file_set_syscall_error(struct mail_index *index,
				      const char *filepath,
				      const char *function);

uint32_t mail_index_uint32_to_offset(uint32_t offset);
uint32_t mail_index_offset_to_uint32(uint32_t offset);

#endif
