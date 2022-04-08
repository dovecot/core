#ifndef MAIL_INDEX_PRIVATE_H
#define MAIL_INDEX_PRIVATE_H

#include "file-lock.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"

#include <sys/stat.h>

struct mail_transaction_header;
struct mail_transaction_log_view;
struct mail_index_sync_map_ctx;

/* How large index files to mmap() instead of reading to memory. */
#define MAIL_INDEX_MMAP_MIN_SIZE (1024*64)
/* How many times to retry opening index files if read/fstat returns ESTALE.
   This happens with NFS when the file has been deleted (ie. index file was
   rewritten by another computer than us). */
#define MAIL_INDEX_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
/* Large extension header sizes are probably caused by file corruption, so
   try to catch them by limiting the header size. */
#define MAIL_INDEX_EXT_HEADER_MAX_SIZE (1024*1024*16-1)

#define MAIL_INDEX_IS_IN_MEMORY(index) \
	((index)->dir == NULL)

#define MAIL_INDEX_MAP_IS_IN_MEMORY(map) \
	((map)->rec_map->mmap_base == NULL)

#define MAIL_INDEX_MAP_IDX(map, idx) \
	((struct mail_index_record *) \
	 PTR_OFFSET((map)->rec_map->records, (idx) * (map)->hdr.record_size))
#define MAIL_INDEX_REC_AT_SEQ(map, seq)					\
	((struct mail_index_record *)					\
	 PTR_OFFSET((map)->rec_map->records, ((seq)-1) * (map)->hdr.record_size))

#define MAIL_TRANSACTION_FLAG_UPDATE_IS_INTERNAL(u) \
	((((u)->add_flags | (u)->remove_flags) & MAIL_INDEX_FLAGS_MASK) == 0 && \
	 (u)->modseq_inc_flag == 0)

#define MAIL_INDEX_EXT_KEYWORDS "keywords"
#define MAIL_INDEX_EXT_NAME_MAX_LENGTH 64

typedef int mail_index_expunge_handler_t(struct mail_index_sync_map_ctx *ctx,
					 const void *data, void **sync_context);

#define MAIL_INDEX_HEADER_SIZE_ALIGN(size) \
	(((size) + 7) & ~7U)

/* In-memory copy of struct mail_index_ext_header */
struct mail_index_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t reset_id;
	uint32_t ext_offset; /* points to beginning of mail_index_ext_header */
	uint32_t hdr_offset; /* points to mail_index_ext_header.data[] */
	uint32_t hdr_size; /* size of mail_index_ext_header.data[] */
	uint16_t record_offset;
	uint16_t record_size;
	uint16_t record_align;
};

struct mail_index_ext_header {
	/* Size of data[], i.e. the extension size in header */
	uint32_t hdr_size;
	/* If reset_id changes, all of the extension record data is
	   invalidated. For example with cache files reset_id must match the
	   cache header's file_seq or the cache offsets aren't valid. */
	uint32_t reset_id;
	/* Offset of this extension in struct mail_index_record. */
	uint16_t record_offset;
	/* Size of this extension in struct mail_index_record. */
	uint16_t record_size;
	/* Required alignment of this extension in struct mail_index_record.
	   It's expected that record_offset is correctly aligned. This is used
	   only when rearranging fields due to adding/removing other
	   extensions. */
	uint16_t record_align;
	/* Size of name[], which contains the extension's unique name. */
	uint16_t name_size;
	/* unsigned char name[name_size]; */
	/* Extension header data, if any. This starts from the next 64-bit
	   aligned offset after name[]. */
	/* unsigned char data[hdr_size]; */
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

struct mail_index_registered_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t hdr_size; /* size of mail_index_ext_header.data[] */
	uint16_t record_size;
	uint16_t record_align;

	mail_index_expunge_handler_t *expunge_handler;
};

struct mail_index_modseq_header {
	/* highest used modseq */
	uint64_t highest_modseq;
	/* last tracked log file position */
	uint32_t log_seq;
	uint32_t log_offset;
};

struct mail_index_record_map {
	ARRAY(struct mail_index_map *) maps;

	void *mmap_base;
	size_t mmap_size, mmap_used_size;

	buffer_t *buffer;

	void *records; /* struct mail_index_record[] */
	unsigned int records_count;

	struct mail_index_map_modseq *modseq;
	uint32_t last_appended_uid;
};

#define MAIL_INDEX_MAP_HDR_OFFSET(map, hdr_offset) \
	CONST_PTR_OFFSET((map)->hdr_copy_buf->data, hdr_offset)
struct mail_index_map {
	struct mail_index *index;
	int refcount;

	/* Copy of the base header for convenience. Note that base_header_size
	   may be smaller or larger than this struct. If it's smaller, the last
	   fields in the struct are filled with zeroes. */
	struct mail_index_header hdr;
	/* Copy of the full header. */
	buffer_t *hdr_copy_buf;

	pool_t extension_pool;
	ARRAY(struct mail_index_ext) extensions;
	ARRAY(uint32_t) ext_id_map; /* index -> file */

	ARRAY(unsigned int) keyword_idx_map; /* file -> index */

	struct mail_index_modseq_header modseq_hdr_snapshot;

	struct mail_index_record_map *rec_map;
};

struct mail_index_module_register {
	unsigned int id;
};

union mail_index_module_context {
	struct mail_index_module_register *reg;
};

struct mail_index_settings {
	/* Directory path for .cache file. Set via
	   mail_index_set_cache_dir(). */
	char *cache_dir;

	/* fsyncing behavior. Set via mail_index_set_fsync_mode(). */
	enum fsync_mode fsync_mode;
	enum mail_index_fsync_mask fsync_mask;

	/* Index file permissions. Set via mail_index_set_permissions(). */
	mode_t mode;
	gid_t gid;
	char *gid_origin;

	/* Lock settings. Set via mail_index_set_lock_method(). */
	enum file_lock_method lock_method;
	unsigned int max_lock_timeout_secs;

	/* Initial extension added to newly created indexes. Set via
	   mail_index_set_ext_init_data(). */
	uint32_t ext_hdr_init_id;
	void *ext_hdr_init_data;
};

struct mail_index_error {
	/* Human-readable error text */
	char *text;

	/* Error happened because there's no disk space, i.e. syscall failed
	   with ENOSPC or EDQUOT. */
	bool nodiskspace:1;
};

struct mail_index {
	/* Directory path for the index, or NULL for in-memory indexes. */
	char *dir;
	/* Filename prefix for the index, e.g. "dovecot.index." */
	char *prefix;
	struct event *event;
	enum mail_index_open_flags flags;
	struct mail_index_settings set;
	struct mail_index_optimization_settings optimization_set;

	struct mail_cache *cache;
	struct mail_transaction_log *log;

	char *filepath;
	int fd;
	/* Linked list of currently opened views */
	struct mail_index_view *views;
	/* Latest map */
	struct mail_index_map *map;

	/* ID number that permanently identifies the index. This is stored in
	   the index files' headers. If the indexids suddenly changes, it means
	   that the index has been completely recreated and needs to be
	   reopened (e.g. the mailbox was deleted and recreated while it
	   was open). */
	uint32_t indexid;
	/* Views initially use this same ID value. This ID is incremented
	   whenever something unexpected happens to the index that prevents
	   syncing existing views. When the view's inconsistency_id doesn't
	   match this one, the view is marked as inconsistent. */
	unsigned int inconsistency_id;
	/* How many times this index has been opened with mail_index_open(). */
	unsigned int open_count;

	/* These contain the log_file_seq and log_file_tail_offset that exists
	   in dovecot.index file's header. These are used to figure out if it's
	   time to rewrite the dovecot.index file. Note that these aren't
	   available in index->map->hdr, because it gets updated when
	   transaction log file is read. */
	uint32_t main_index_hdr_log_file_seq;
	uint32_t main_index_hdr_log_file_tail_offset;

	/* log file which last updated index_deleted */
	uint32_t index_delete_changed_file_seq;

	/* transaction log head seq/offset when we last fscked */
	uint32_t fsck_log_head_file_seq;
	uoff_t fsck_log_head_file_offset;

	/* syncing will update this if non-NULL */
	struct mail_index_transaction_commit_result *sync_commit_result;
	/* Delayed log2_rotate_time update to mail_index_header. This is set
	   and unset within the same sync. */
	uint32_t hdr_log2_rotate_time_delayed_update;

	/* Registered extensions */
	pool_t extension_pool;
	ARRAY(struct mail_index_registered_ext) extensions;

	/* All keywords that have ever been used in this index. Keywords are
	   only added here, never removed. */
	pool_t keywords_pool;
	ARRAY_TYPE(keywords) keywords;
	HASH_TABLE(char *, void *) keywords_hash; /* name -> unsigned int idx */

	/* Registered extension IDs */
	uint32_t keywords_ext_id;
	uint32_t modseq_ext_id;

	/* Module-specific contexts. */
	ARRAY(union mail_index_module_context *) module_contexts;

	/* Last error returned by mail_index_get_error_message().
	   Cleared by mail_index_reset_error(). */
	struct mail_index_error last_error;
	/* Timestamp when mmap() failure was logged the last time. This is used
	   to prevent logging the same error too rapidly. This could happen
	   e.g. if mmap()ing a large cache file that exceeeds process's
	   VSZ limit. */
	time_t last_mmap_error_time;
	/* If non-NULL, dovecot.index should be recreated as soon as possible.
	   The reason for why the recreation is wanted is stored as human-
	   readable text. */
	char *need_recreate;

	/* Mapping has noticed non-external MAIL_TRANSACTION_INDEX_DELETED
	   record, i.e. a request to mark the index deleted. The next sync
	   will finish the deletion by writing external
	   MAIL_TRANSACTION_INDEX_DELETED record. */
	bool index_delete_requested:1;
	/* Mapping has noticed external MAIL_TRANSACTION_INDEX_DELETED record,
	   or index was unexpectedly deleted under us. No more changes are
	   allowed to the index, except undeletion. */
	bool index_deleted:1;
	/* .log is locked for syncing. This is the main exclusive lock for
	   indexes. */
	bool log_sync_locked:1;
	/* Main index or .log couldn't be opened read-write */
	bool readonly:1;
	/* mail_index_map() is running */
	bool mapping:1;
	/* mail_index_sync_*() is running */
	bool syncing:1;
	/* Mapping has read more from .log than it preferred. Use
	   mail_index_base_optimization_settings.rewrite_min_log_bytes the next
	   time when checking if index needs a rewrite. */
	bool index_min_write:1;
	/* mail_index_modseq_enable() has been called. Track per-flag
	   modseq numbers in memory (global modseqs are tracked anyway). */
	bool modseqs_enabled:1;
	/* mail_index_open() is creating new index files */
	bool initial_create:1;
	/* TRUE after mail_index_map() has succeeded */
	bool initial_mapped:1;
	/* The next mail_index_map() must reopen the main index, because the
	   currently opened one is too old. */
	bool reopen_main_index:1;
	/* Index has been fsck'd, but mail_index_reset_fscked() hasn't been
	   called yet. */
	bool fscked:1;
};

extern struct mail_index_module_register mail_index_module_register;
extern struct event_category event_category_mail_index;

/* Add/replace expunge handler for specified extension. */
void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id,
					 mail_index_expunge_handler_t *callback);
void mail_index_unregister_expunge_handler(struct mail_index *index,
					   uint32_t ext_id);

int mail_index_create_tmp_file(struct mail_index *index,
			       const char *path_prefix, const char **path_r);

int mail_index_try_open_only(struct mail_index *index);
void mail_index_close_file(struct mail_index *index);
/* Returns 1 if index was successfully (re-)opened, 0 if the index no longer
   exists, -1 if I/O error. If 1 is returned, reopened_r=TRUE if a new index
   was actually reopened (or if index wasn't even open before this call). */
int mail_index_reopen_if_changed(struct mail_index *index, bool *reopened_r,
				 const char **reason_r);
/* Update/rewrite the main index file from index->map */
void mail_index_write(struct mail_index *index, bool want_rotate,
		      const char *reason);

void mail_index_flush_read_cache(struct mail_index *index, const char *path,
				 int fd, bool locked);

int mail_index_lock_fd(struct mail_index *index, const char *path, int fd,
		       int lock_type, unsigned int timeout_secs,
		       struct file_lock **lock_r);

/* Allocate a new empty map. */
struct mail_index_map *mail_index_map_alloc(struct mail_index *index);
/* Replace index->map with the latest index changes. This may reopen the index
   file and/or it may read the latest changes from transaction log. The log is
   read up to EOF, but non-synced expunges are skipped.

   If we mmap()ed the index file, the map is returned locked.

   Returns 1 = ok, 0 = corrupted, -1 = error. */
int mail_index_map(struct mail_index *index,
		   enum mail_index_sync_handler_type type);
/* Unreference given mapping and unmap it if it's dropped to zero. */
void mail_index_unmap(struct mail_index_map **map);
/* Clone a map. It still points to the original rec_map. */
struct mail_index_map *mail_index_map_clone(const struct mail_index_map *map);
/* Make sure the map has its own private rec_map, cloning it if necessary. */
void mail_index_record_map_move_to_private(struct mail_index_map *map);
/* If map points to mmap()ed index, copy it to the memory. */
void mail_index_map_move_to_memory(struct mail_index_map *map);

void mail_index_fchown(struct mail_index *index, int fd, const char *path);

bool mail_index_map_lookup_ext(struct mail_index_map *map, const char *name,
			       uint32_t *idx_r);
bool mail_index_ext_name_is_valid(const char *name);
uint32_t
mail_index_map_register_ext(struct mail_index_map *map,
			    const char *name, uint32_t ext_offset,
			    const struct mail_index_ext_header *ext_hdr);
bool mail_index_map_get_ext_idx(struct mail_index_map *map,
				uint32_t ext_id, uint32_t *idx_r);
const struct mail_index_ext *
mail_index_view_get_ext(struct mail_index_view *view, uint32_t ext_id);

void mail_index_map_lookup_seq_range(struct mail_index_map *map,
				     uint32_t first_uid, uint32_t last_uid,
				     uint32_t *first_seq_r,
				     uint32_t *last_seq_r);

/* Returns 1 on success, 0 on non-critical errors we want to silently fix,
   -1 if map isn't usable. The caller is responsible for logging the errors
   if -1 is returned. */
int mail_index_map_check_header(struct mail_index_map *map,
				const char **error_r);
/* Returns 1 if header is usable, 0 or -1 if not. The caller should log an
   error if -1 is returned, but not if 0 is returned. */
bool mail_index_check_header_compat(struct mail_index *index,
				    const struct mail_index_header *hdr,
				    uoff_t file_size, const char **error_r);
int mail_index_map_parse_extensions(struct mail_index_map *map);
int mail_index_map_parse_keywords(struct mail_index_map *map);

void mail_index_map_init_extbufs(struct mail_index_map *map,
				 unsigned int initial_count);
int mail_index_map_ext_get_next(struct mail_index_map *map,
				unsigned int *offset,
				const struct mail_index_ext_header **ext_hdr_r,
				const char **name_r);
int mail_index_map_ext_hdr_check(const struct mail_index_header *hdr,
				 const struct mail_index_ext_header *ext_hdr,
				 const char *name, const char **error_r);
unsigned int mail_index_map_ext_hdr_offset(unsigned int name_len);

void mail_index_fsck_locked(struct mail_index *index);

/* Log an error and set it as the index's current error that is available
   with mail_index_get_error_message(). */
void mail_index_set_error(struct mail_index *index, const char *fmt, ...)
	ATTR_FORMAT(2, 3) ATTR_COLD;
/* Same as mail_index_set_error(), but don't log the error. */
void mail_index_set_error_nolog(struct mail_index *index, const char *str)
	ATTR_COLD;
/* "%s failed with index file %s: %m" */
void mail_index_set_syscall_error(struct mail_index *index,
				  const char *function) ATTR_COLD;
/* "%s failed with file %s: %m" */
void mail_index_file_set_syscall_error(struct mail_index *index,
				       const char *filepath,
				       const char *function) ATTR_COLD;

#endif
