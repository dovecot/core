#ifndef __MAIL_INDEX_PRIVATE_H
#define __MAIL_INDEX_PRIVATE_H

#include "file-dotlock.h"
#include "mail-index.h"

struct mail_transaction_header;

/* number of records to always keep allocated in index file,
   either used or unused */
#define INDEX_MIN_RECORDS_COUNT 64
/* when empty space in index file gets full, grow the file n% larger */
#define INDEX_GROW_PERCENTAGE 10
/* ftruncate() the index file when only n% of it is in use */
#define INDEX_TRUNCATE_PERCENTAGE 30
/* don't truncate whole file anyway, keep n% of the empty space */
#define INDEX_TRUNCATE_KEEP_PERCENTAGE 10
/* Compress the file when deleted space reaches n% of total size */
#define INDEX_COMPRESS_PERCENTAGE 50
/* Compress the file when searching deleted records tree has to go this deep */
#define INDEX_COMPRESS_DEPTH 10
/* How many times to retry opening index files if read/fstat returns ESTALE.
   This happens with NFS when the file has been deleted (ie. index file was
   rewritten by another computer than us). */
#define INDEX_ESTALE_RETRY_COUNT 10

enum mail_index_mail_flags {
	MAIL_INDEX_MAIL_FLAG_DIRTY = 0x80,
	MAIL_INDEX_MAIL_FLAG_EXPUNGED = 0x40,
	MAIL_INDEX_MAIL_FLAG_NONRECENT = MAIL_RECENT
};

#define MAIL_INDEX_MAP_IS_IN_MEMORY(map) \
	((map)->buffer != NULL)

struct mail_index_map {
	int refcount;

	const struct mail_index_header *hdr;
	struct mail_index_record *records;
	unsigned int records_count;

	void *mmap_base;
	size_t file_size, file_used_size;

	buffer_t *buffer;

	uint32_t log_file_seq;
	uoff_t log_file_offset;

	struct mail_index_header hdr_copy;
	unsigned int write_to_disk:1;
};

struct mail_index {
	char *dir, *prefix;

	struct mail_cache *cache;
	struct mail_transaction_log *log;

	mode_t mode;
	gid_t gid;

	char *filepath;
	int fd;

        struct mail_index_map *map;
	const struct mail_index_header *hdr;
	uint32_t indexid;

	int lock_type, shared_lock_count, excl_lock_count;
	unsigned int lock_id, copy_lock_id;
	char *copy_lock_path;
	struct dotlock dotlock;

	char *error;
	unsigned int nodiskspace:1;
	unsigned int index_lock_timeout:1;

	unsigned int opened:1;
	unsigned int log_locked:1;
	unsigned int mmap_disable:1;
	unsigned int mmap_no_write:1;
	unsigned int fcntl_locks_disable:1;
	unsigned int readonly:1;
	unsigned int fsck:1;
};

void mail_index_header_init(struct mail_index_header *hdr);
int mail_index_write_header(struct mail_index *index,
			    const struct mail_index_header *hdr);

int mail_index_create(struct mail_index *index, struct mail_index_header *hdr);
int mail_index_try_open(struct mail_index *index, unsigned int *lock_id_r);
int mail_index_create_tmp_file(struct mail_index *index, const char **path_r);

/* Returns 0 = ok, -1 = error. If update_index is TRUE, reopens the index
   file if needed to get later version of it (not necessarily latest due to
   races, unless transaction log is exclusively locked). */
int mail_index_lock_shared(struct mail_index *index, int update_index,
			   unsigned int *lock_id_r);
/* Returns 1 = ok, 0 = already synced up to given log_file_offset, -1 = error */
int mail_index_lock_exclusive(struct mail_index *index,
			      uint32_t log_file_seq, uoff_t log_file_offset,
			      unsigned int *lock_id_r);
void mail_index_unlock(struct mail_index *index, unsigned int lock_id);
/* Returns 1 if given lock_id is valid, 0 if not. */
int mail_index_is_locked(struct mail_index *index, unsigned int lock_id);

/* Map index file to memory, replacing the previous mapping for index.
   Returns 1 = ok, 0 = corrupted, -1 = error. If index needs fscking, it
   returns 1 but sets index->fsck = TRUE. */
int mail_index_map(struct mail_index *index, int force);
/* Unreference given mapping and unmap it if it's dropped to zero. */
void mail_index_unmap(struct mail_index *index, struct mail_index_map *map);
struct mail_index_map *mail_index_map_to_memory(struct mail_index_map *map);

void mail_index_update_cache(struct mail_index_transaction *t,
			     uint32_t seq, uint32_t offset);

int mail_index_fix_header(struct mail_index *index, struct mail_index_map *map,
			  struct mail_index_header *hdr, const char **error_r);

void mail_index_view_transaction_ref(struct mail_index_view *view);
void mail_index_view_transaction_unref(struct mail_index_view *view);

int mail_index_sync_get_rec(struct mail_index_view *view,
			    struct mail_index_sync_rec *rec,
			    const struct mail_transaction_header *hdr,
			    const void *data, size_t *data_offset);

void mail_index_set_inconsistent(struct mail_index *index);
int mail_index_mark_corrupted(struct mail_index *index);

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

#endif
