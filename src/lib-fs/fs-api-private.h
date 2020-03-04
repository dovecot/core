#ifndef FS_API_PRIVATE_H
#define FS_API_PRIVATE_H

#include "fs-api.h"
#include "fs-wrapper.h"
#include "module-context.h"

#include <sys/time.h>

#define FS_EVENT_FIELD_FS "lib-fs#fs"
#define FS_EVENT_FIELD_FILE "lib-fs#file"
#define FS_EVENT_FIELD_ITER "lib-fs#iter"

enum fs_get_metadata_flags {
	FS_GET_METADATA_FLAG_DUMMY,
};

struct fs_api_module_register {
	unsigned int id;
};

union fs_api_module_context {
	struct fs_api_module_register *reg;
};

extern struct fs_api_module_register fs_api_module_register;

struct fs_vfuncs {
	struct fs *(*alloc)(void);
	int (*init)(struct fs *fs, const char *args,
		    const struct fs_settings *set, const char **error_r);
	void (*deinit)(struct fs *fs);

	enum fs_properties (*get_properties)(struct fs *fs);

	struct fs_file *(*file_alloc)(void);
	void (*file_init)(struct fs_file *file, const char *path,
			  enum fs_open_mode mode, enum fs_open_flags flags);
	void (*file_deinit)(struct fs_file *file);
	void (*file_close)(struct fs_file *file);
	const char *(*get_path)(struct fs_file *file);

	void (*set_async_callback)(struct fs_file *file,
				   fs_file_async_callback_t *callback,
				   void *context);
	void (*wait_async)(struct fs *fs);

	void (*set_metadata)(struct fs_file *file, const char *key,
			     const char *value);
	int (*get_metadata)(struct fs_file *file,
			    enum fs_get_metadata_flags flags,
			    const ARRAY_TYPE(fs_metadata) **metadata_r);

	bool (*prefetch)(struct fs_file *file, uoff_t length);
	ssize_t (*read)(struct fs_file *file, void *buf, size_t size);
	struct istream *(*read_stream)(struct fs_file *file,
				       size_t max_buffer_size);

	int (*write)(struct fs_file *file, const void *data, size_t size);
	void (*write_stream)(struct fs_file *file);
	/* After write_stream_finish() is called once, all the following
	   (async) calls will have success==TRUE. */
	int (*write_stream_finish)(struct fs_file *file, bool success);

	int (*lock)(struct fs_file *file, unsigned int secs,
		    struct fs_lock **lock_r);
	void (*unlock)(struct fs_lock *lock);

	int (*exists)(struct fs_file *file);
	int (*stat)(struct fs_file *file, struct stat *st_r);
	int (*copy)(struct fs_file *src, struct fs_file *dest);
	int (*rename)(struct fs_file *src, struct fs_file *dest);
	int (*delete_file)(struct fs_file *file);

	struct fs_iter *(*iter_alloc)(void);
	void (*iter_init)(struct fs_iter *iter, const char *path,
			  enum fs_iter_flags flags);
	const char *(*iter_next)(struct fs_iter *iter);
	int (*iter_deinit)(struct fs_iter *iter);

	bool (*switch_ioloop)(struct fs *fs);
	int (*get_nlinks)(struct fs_file *file, nlink_t *nlinks_r);
};

struct fs {
	struct fs *parent; /* for wrapper filesystems */
	const char *name;
	struct fs_vfuncs v;
	char *temp_path_prefix;
	int refcount;

	char *username, *session_id;

	struct fs_settings set;

	/* may be used by fs_wait_async() to do the waiting */
	struct ioloop *wait_ioloop, *prev_ioloop;

	unsigned int files_open_count;
	struct fs_file *files;
	struct fs_iter *iters;
	struct event *event;

	struct fs_stats stats;

	ARRAY(union fs_api_module_context *) module_contexts;
};

struct fs_file {
	/* linked list of all files */
	struct fs_file *prev, *next;

	struct fs_file *parent; /* for wrapper filesystems */
	struct fs *fs;
	struct ostream *output;
	struct event *event;
	char *path;
	char *last_error;
	enum fs_open_flags flags;

	struct istream *seekable_input;
	struct istream *pending_read_input;

	const struct hash_method *write_digest_method;
	void *write_digest;

	pool_t metadata_pool;
	ARRAY_TYPE(fs_metadata) metadata;

	struct fs_file *copy_src;
	struct istream *copy_input;
	struct ostream *copy_output;

	struct timeval timing_start[FS_OP_COUNT];

	bool write_pending:1;
	bool writing_stream:1;
	bool metadata_changed:1;

	bool read_or_prefetch_counted:1;
	bool lookup_metadata_counted:1;
	bool stat_counted:1;
	bool istream_open:1;
	bool last_error_changed:1;
};

struct fs_lock {
	struct fs_file *file;
};

struct fs_iter {
	/* linked list of all iters */
	struct fs_iter *prev, *next;

	struct fs *fs;
	struct event *event;
	enum fs_iter_flags flags;
	struct timeval start_time;
	char *last_error;

	bool async_have_more;
	fs_file_async_callback_t *async_callback;
	void *async_context;
};

extern const struct fs fs_class_dict;
extern const struct fs fs_class_posix;
extern const struct fs fs_class_randomfail;
extern const struct fs fs_class_metawrap;
extern const struct fs fs_class_sis;
extern const struct fs fs_class_sis_queue;
extern const struct fs fs_class_test;

void fs_class_register(const struct fs *fs_class);

/* Event must be fs_file or fs_iter events. Set errno from err. */
void fs_set_error(struct event *event, int err,
		  const char *fmt, ...) ATTR_FORMAT(3, 4);
/* Like fs_set_error(), but use the existing errno. */
void fs_set_error_errno(struct event *event, const char *fmt, ...) ATTR_FORMAT(2, 3);
void fs_file_set_error_async(struct fs_file *file);

ssize_t fs_read_via_stream(struct fs_file *file, void *buf, size_t size);
int fs_write_via_stream(struct fs_file *file, const void *data, size_t size);
void fs_metadata_init(struct fs_file *file);
void fs_metadata_init_or_clear(struct fs_file *file);
void fs_default_set_metadata(struct fs_file *file,
			     const char *key, const char *value);
int fs_get_metadata_full(struct fs_file *file,
			 enum fs_get_metadata_flags flags,
			 const ARRAY_TYPE(fs_metadata) **metadata_r);
const char *fs_metadata_find(const ARRAY_TYPE(fs_metadata) *metadata,
			     const char *key);
int fs_default_copy(struct fs_file *src, struct fs_file *dest);

void fs_file_timing_end(struct fs_file *file, enum fs_op op);

struct fs_file *
fs_file_init_parent(struct fs_file *parent, const char *path, int mode_flags);
struct fs_iter *
fs_iter_init_parent(struct fs_iter *parent,
		    const char *path, enum fs_iter_flags flags);
void fs_file_free(struct fs_file *file);

/* Same as fs_write_stream_abort_error(), except it closes the *parent* file
   and error is left untouched */
void fs_write_stream_abort_parent(struct fs_file *file, struct ostream **output);

#endif
