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

typedef int mail_index_expunge_handler_t(struct mail_index_sync_map_ctx *ctx,
					 uint32_t seq, const void *data,
					 void **sync_context, void *context);
typedef void mail_index_sync_lost_handler_t(struct mail_index *index);

#define MAIL_INDEX_HEADER_SIZE_ALIGN(size) \
	(((size) + 7) & ~7)

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

struct mail_index_registered_ext {
	const char *name;
	uint32_t index_idx; /* index ext_id */
	uint32_t hdr_size; /* size of mail_index_ext_header.data[] */
	uint16_t record_size;
	uint16_t record_align;

	mail_index_expunge_handler_t *expunge_handler;

	void *expunge_context;
	bool expunge_handler_call_always:1;
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

struct mail_index_map {
	struct mail_index *index;
	int refcount;

	struct mail_index_header hdr;
	const void *hdr_base;
	buffer_t *hdr_copy_buf;

	pool_t extension_pool;
	ARRAY(struct mail_index_ext) extensions;
	ARRAY(uint32_t) ext_id_map; /* index -> file */

	ARRAY(unsigned int) keyword_idx_map; /* file -> index */

	struct mail_index_record_map *rec_map;
};

struct mail_index_module_register {
	unsigned int id;
};

union mail_index_module_context {
	struct mail_index_module_register *reg;
};

struct mail_index {
	char *dir, *prefix;
	char *cache_dir;
	struct event *event;

	struct mail_cache *cache;
	struct mail_transaction_log *log;

	unsigned int open_count;
	enum mail_index_open_flags flags;
	enum fsync_mode fsync_mode;
	enum mail_index_fsync_mask fsync_mask;
	mode_t mode;
	gid_t gid;
	char *gid_origin;

	struct mail_index_optimization_settings optimization_set;
	uint32_t pending_log2_rotate_time;

	pool_t extension_pool;
	ARRAY(struct mail_index_registered_ext) extensions;

	uint32_t ext_hdr_init_id;
	void *ext_hdr_init_data;

	ARRAY(mail_index_sync_lost_handler_t *) sync_lost_handlers;

	char *filepath;
	int fd;

	struct mail_index_map *map;
	char *need_recreate;

	time_t last_mmap_error_time;

	uint32_t indexid;
	unsigned int inconsistency_id;

	/* last_read_log_file_* contains the seq/offsets we last read from
	   the main index file's headers. these are used to figure out when
	   the main index file should be updated. */
	uint32_t last_read_log_file_seq;
	uint32_t last_read_log_file_tail_offset;

	/* transaction log head seq/offset when we last fscked */
	uint32_t fsck_log_head_file_seq;
	uoff_t fsck_log_head_file_offset;

	/* syncing will update this if non-NULL */
	struct mail_index_transaction_commit_result *sync_commit_result;

	enum file_lock_method lock_method;
	unsigned int max_lock_timeout_secs;

	pool_t keywords_pool;
	ARRAY_TYPE(keywords) keywords;
	HASH_TABLE(char *, void *) keywords_hash; /* name -> unsigned int idx */

	uint32_t keywords_ext_id;
	uint32_t modseq_ext_id;

	struct mail_index_view *views;

	/* Module-specific contexts. */
	ARRAY(union mail_index_module_context *) module_contexts;

	char *error;
	bool nodiskspace:1;
	bool index_lock_timeout:1;

	bool index_delete_requested:1; /* next sync sets it deleted */
	bool index_deleted:1; /* no changes allowed anymore */
	bool log_sync_locked:1;
	bool readonly:1;
	bool mapping:1;
	bool syncing:1;
	bool index_min_write:1;
	bool modseqs_enabled:1;
	bool initial_create:1;
	bool initial_mapped:1;
	bool reopen_main_index:1;
	bool fscked:1;
};

extern struct mail_index_module_register mail_index_module_register;
extern struct event_category event_category_mail_index;

/* Add/replace sync handler for specified extra record. */
void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id, bool call_always,
					 mail_index_expunge_handler_t *callback,
					 void *context);
void mail_index_unregister_expunge_handler(struct mail_index *index,
					   uint32_t ext_id);
void mail_index_register_sync_lost_handler(struct mail_index *index,
					   mail_index_sync_lost_handler_t *cb);
void mail_index_unregister_sync_lost_handler(struct mail_index *index,
					mail_index_sync_lost_handler_t *cb);

int mail_index_create_tmp_file(struct mail_index *index,
			       const char *path_prefix, const char **path_r);

int mail_index_try_open_only(struct mail_index *index);
void mail_index_close_file(struct mail_index *index);
int mail_index_reopen_if_changed(struct mail_index *index,
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

/* Clone a map. The returned map is always in memory. */
struct mail_index_map *mail_index_map_clone(const struct mail_index_map *map);
void mail_index_record_map_move_to_private(struct mail_index_map *map);
/* Move a mmaped map to memory. */
void mail_index_map_move_to_memory(struct mail_index_map *map);
void mail_index_fchown(struct mail_index *index, int fd, const char *path);

bool mail_index_map_lookup_ext(struct mail_index_map *map, const char *name,
			       uint32_t *idx_r);
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

void mail_index_view_transaction_ref(struct mail_index_view *view);
void mail_index_view_transaction_unref(struct mail_index_view *view);

void mail_index_fsck_locked(struct mail_index *index);

/* Log an error and set it as the index's current error that is available
   with mail_index_get_error_message(). */
void mail_index_set_error(struct mail_index *index, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
/* Same as mail_index_set_error(), but don't log the error. */
void mail_index_set_error_nolog(struct mail_index *index, const char *str);
/* "%s failed with index file %s: %m" */
void mail_index_set_syscall_error(struct mail_index *index,
				  const char *function);
/* "%s failed with file %s: %m" */
void mail_index_file_set_syscall_error(struct mail_index *index,
				       const char *filepath,
				       const char *function);

#endif
