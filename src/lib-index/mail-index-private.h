#ifndef __MAIL_INDEX_PRIVATE_H
#define __MAIL_INDEX_PRIVATE_H

/* Make sure F_RDLCK, F_WRLCK and F_UNLCK get defined */
#include <unistd.h>
#include <fcntl.h>

#include "file-dotlock.h"
#include "mail-index.h"

struct mail_transaction_header;
struct mail_index_sync_map_ctx;

/* How many seconds to wait a lock for index file. */
#define MAIL_INDEX_LOCK_SECS 120
/* Index file is grown exponentially when we're adding less than this many
   records. */
#define MAIL_INDEX_MAX_POWER_GROW (1024*1024 / sizeof(struct mail_index_record))
/* How many times to retry opening index files if read/fstat returns ESTALE.
   This happens with NFS when the file has been deleted (ie. index file was
   rewritten by another computer than us). */
#define MAIL_INDEX_ESTALE_RETRY_COUNT 10

#define MAIL_INDEX_MAP_IS_IN_MEMORY(map) \
	((map)->buffer != NULL)

#define MAIL_INDEX_MAP_IDX(map, idx) \
	((struct mail_index_record *) \
		PTR_OFFSET((map)->records, (idx) * (map)->hdr.record_size))

typedef int mail_index_expunge_handler_t(struct mail_index_sync_map_ctx *ctx,
					 uint32_t seq, const void *data,
					 void **context);
typedef int mail_index_sync_handler_t(struct mail_index_sync_map_ctx *ctx,
				      uint32_t seq, void *old_data,
				      const void *new_data, void **context);

#define MAIL_INDEX_HEADER_SIZE_ALIGN(size) \
	(((size) + 7) & ~7)

struct mail_index_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t reset_id;
	uint32_t hdr_offset;
	uint32_t hdr_size;
	uint16_t record_offset;
	uint16_t record_size;
	uint16_t record_align;
};

struct mail_index_ext_header {
	uint32_t hdr_size;
	uint32_t reset_id;
	uint16_t record_offset;
	uint16_t record_size;
	uint16_t record_align;
	uint16_t name_size;
	/* unsigned char name[] */
};

struct mail_index_map {
	int refcount;

	struct mail_index_header hdr;
	const void *hdr_base;
	void *records; /* struct mail_index_record[] */
	unsigned int records_count;

	pool_t extension_pool;
	buffer_t *extensions; /* struct mail_index_ext[] */
	buffer_t *ext_id_map; /* uint32_t[] (index -> file) */

	void *mmap_base;
	size_t mmap_size, mmap_used_size;

	buffer_t *buffer;
	buffer_t *hdr_copy_buf;

	unsigned int write_to_disk:1;
};

struct mail_index {
	char *dir, *prefix;

	struct mail_cache *cache;
	struct mail_transaction_log *log;

	mode_t mode;
	gid_t gid;

	pool_t extension_pool;
	buffer_t *extensions; /* struct mail_index_ext[] */

	buffer_t *expunge_handlers; /* mail_index_expunge_handler_t*[] */
	buffer_t *sync_handlers; /* mail_index_sync_handler_t*[] */

	char *filepath;
	int fd;

        struct mail_index_map *map;
	const struct mail_index_header *hdr;
	uint32_t indexid;

	int lock_type, shared_lock_count, excl_lock_count;
	unsigned int lock_id;
	char *copy_lock_path;
	struct dotlock dotlock;
        enum mail_index_lock_method lock_method;

	/* These are typically same as map->hdr->log_file_*, but with
	   mmap_disable we may have synced more than index */
	uint32_t sync_log_file_seq;
	uoff_t sync_log_file_offset;

	unsigned int last_grow_count;

	char *error;
	unsigned int nodiskspace:1;
	unsigned int index_lock_timeout:1;

	unsigned int opened:1;
	unsigned int log_locked:1;
	unsigned int mmap_disable:1;
	unsigned int mmap_no_write:1;
	unsigned int readonly:1;
	unsigned int fsck:1;
};

enum mail_index_sync_handler_type {
	MAIL_INDEX_SYNC_HANDLER_INDEX	= 0x01,
	MAIL_INDEX_SYNC_HANDLER_VIEW	= 0x02
};

struct mail_index_sync_handler {
	mail_index_sync_handler_t *callback;
        enum mail_index_sync_handler_type type;
};

/* Add/replace sync handler for specified extra record. */
void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id,
					 mail_index_expunge_handler_t *cb);
void mail_index_register_sync_handler(struct mail_index *index, uint32_t ext_id,
				      mail_index_sync_handler_t *cb,
				      enum mail_index_sync_handler_type type);

int mail_index_write_base_header(struct mail_index *index,
				 const struct mail_index_header *hdr);

int mail_index_reopen(struct mail_index *index, int fd);
int mail_index_create_tmp_file(struct mail_index *index, const char **path_r);

/* Returns 0 = ok, -1 = error. If update_index is TRUE, reopens the index
   file if needed to get later version of it (not necessarily latest due to
   races, unless transaction log is exclusively locked). */
int mail_index_lock_shared(struct mail_index *index, int update_index,
			   unsigned int *lock_id_r);
/* Returns 0 = ok, -1 = error. */
int mail_index_lock_exclusive(struct mail_index *index,
			      unsigned int *lock_id_r);
void mail_index_unlock(struct mail_index *index, unsigned int lock_id);
/* Returns 1 if given lock_id is valid, 0 if not. */
int mail_index_is_locked(struct mail_index *index, unsigned int lock_id);

int mail_index_lock_fd(struct mail_index *index, int fd, int lock_type,
		       unsigned int timeout_secs);

/* Reopen index file if it has changed. */
int mail_index_refresh(struct mail_index *index);

/* Map index file to memory, replacing the previous mapping for index.
   Returns 1 = ok, 0 = corrupted, -1 = error. If index needs fscking, it
   returns 1 but sets index->fsck = TRUE. */
int mail_index_map(struct mail_index *index, int force);
/* Unreference given mapping and unmap it if it's dropped to zero. */
void mail_index_unmap(struct mail_index *index, struct mail_index_map *map);
struct mail_index_map *
mail_index_map_clone(struct mail_index_map *map, uint32_t new_record_size);

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

int mail_index_fix_header(struct mail_index *index, struct mail_index_map *map,
			  struct mail_index_header *hdr, const char **error_r);

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
void mail_index_reset_error(struct mail_index *index);

uint32_t mail_index_uint32_to_offset(uint32_t offset);
uint32_t mail_index_offset_to_uint32(uint32_t offset);

#endif
