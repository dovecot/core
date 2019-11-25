#ifndef FS_API_H
#define FS_API_H

struct stat;
struct fs;
struct fs_file;
struct fs_lock;
struct hash_method;

/* Metadata with this prefix shouldn't actually be sent to storage. */
#define FS_METADATA_INTERNAL_PREFIX ":/X-Dovecot-fs-api-"
/* fs_write*() may return a hex-encoded object ID after write is finished.
   This can be later on used to optimize reads by setting it before reading
   the file. */
#define FS_METADATA_OBJECTID FS_METADATA_INTERNAL_PREFIX"ObjectID"
/* Calling this before fs_write_stream_finish() allows renaming the filename.
   This can be useful if you don't know the final filename before writing it
   (e.g. filename contains the file size). The given filename must include the
   full path also. */
#define FS_METADATA_WRITE_FNAME FS_METADATA_INTERNAL_PREFIX"WriteFilename"
/* Original path of the file. The path that's eventually visible to a fs
   backend may be something different, e.g. object ID. This allows the backend
   to still access the original path. */
#define FS_METADATA_ORIG_PATH FS_METADATA_INTERNAL_PREFIX"OrigPath"

enum fs_properties {
	FS_PROPERTY_METADATA	= 0x01,
	FS_PROPERTY_LOCKS	= 0x02,
	FS_PROPERTY_FASTCOPY	= 0x04,
	FS_PROPERTY_RENAME	= 0x08,
	FS_PROPERTY_STAT	= 0x10,
	/* Iteration is possible */
	FS_PROPERTY_ITER	= 0x20,
	/* Iteration always returns all of the files (instead of possibly
	   slightly out of date view) */
	FS_PROPERTY_RELIABLEITER= 0x40,
	/* Backend uses directories, which aren't automatically deleted
	   when its children are deleted. */
	FS_PROPERTY_DIRECTORIES	= 0x80,
	FS_PROPERTY_WRITE_HASH_MD5	= 0x100,
	FS_PROPERTY_WRITE_HASH_SHA256	= 0x200,
	/* fs_copy() will copy the metadata if fs_set_metadata() hasn't
	   been explicitly called. */
	FS_PROPERTY_COPY_METADATA	= 0x400,
	/* Backend support asynchronous file operations. */
	FS_PROPERTY_ASYNC		= 0x800,
	/* Backend supports FS_ITER_FLAG_OBJECTIDS. */
	FS_PROPERTY_OBJECTIDS		= 0x1000,
	/* fs_copy() is fast even when file's metadata is changed */
	FS_PROPERTY_FASTCOPY_CHANGED_METADATA = 0x2000,
};

enum fs_open_mode {
	/* Open only for reading, or fail with ENOENT if it doesn't exist */
	FS_OPEN_MODE_READONLY,
	/* Create a new file, fail with EEXIST if it already exists */
	FS_OPEN_MODE_CREATE,
	/* Create a new file with a new unique name. The generated name is a
	   128bit hex-encoded string. The fs_open()'s path parameter specifies
	   only the directory where the file is created to. */
	FS_OPEN_MODE_CREATE_UNIQUE_128,
	/* Create or replace a file */
	FS_OPEN_MODE_REPLACE,
	/* Append to existing file, fail with ENOENT if it doesn't exist */
	FS_OPEN_MODE_APPEND

#define FS_OPEN_MODE_MASK 0x0f
};

enum fs_open_flags {
	/* File is important and writing must call fsync() or have equivalent
	   behavior. */
	FS_OPEN_FLAG_FSYNC		= 0x10,
	/* Asynchronous writes: fs_write() will fail with EAGAIN if it needs to
	   be called again (the retries can use size=0). For streams
	   fs_write_stream_finish() may request retrying with 0.

	   Asynchronous reads: fs_read() will fail with EAGAIN if it's not
	   finished and fs_read_stream() returns a nonblocking stream. */
	FS_OPEN_FLAG_ASYNC		= 0x20,
	/* fs_read_stream() must return a seekable input stream */
	FS_OPEN_FLAG_SEEKABLE		= 0x40,
	/* Backend should handle this file's operations immediately without
	   any additional command queueing. The caller is assumed to be the one
	   doing any rate limiting if needed. This flag can only be used with
	   ASYNC flag, synchronous requests are never queued. */
	FS_OPEN_FLAG_ASYNC_NOQUEUE	= 0x80
};

enum fs_iter_flags {
	/* Iterate only directories, not files */
	FS_ITER_FLAG_DIRS	= 0x01,
	/* Request asynchronous iteration. */
	FS_ITER_FLAG_ASYNC	= 0x02,
	/* Instead of returning object names, return <objectid>/<object name>.
	   If this isn't supported, the <objectid> is returned empty. The
	   object IDs are always hex-encoded data. This flag can be used only
	   if FS_PROPERTY_OBJECTIDS is enabled. */
	FS_ITER_FLAG_OBJECTIDS	= 0x04,
	/* Explicitly disable all caching for this iteration (if anything
	   happens to be enabled). This should be used only in situations where
	   the iteration is used to fix something that is broken, e.g. doveadm
	   force-resync. */
	FS_ITER_FLAG_NOCACHE	= 0x08
};

enum fs_op {
	FS_OP_WAIT,
	FS_OP_METADATA,
	FS_OP_PREFETCH,
	FS_OP_READ,
	FS_OP_WRITE,
	FS_OP_LOCK,
	FS_OP_EXISTS,
	FS_OP_STAT,
	FS_OP_COPY,
	FS_OP_RENAME,
	FS_OP_DELETE,
	FS_OP_ITER,

	FS_OP_COUNT
};

struct fs_settings {
	/* Username and session ID are mainly used for debugging/logging,
	   but may also be useful for other purposes if they exist (they
	   may be NULL). */
	const char *username;
	const char *session_id;

	/* Dovecot instance's base_dir */
	const char *base_dir;
	/* Directory where temporary files can be created at any time
	   (e.g. /tmp or mail_temp_dir) */
	const char *temp_dir;
	/* SSL client settings. */
	const struct ssl_iostream_settings *ssl_client_set;

	/* Automatically try to rmdir() directories up to this path when
	   deleting files. */
	const char *root_path;
	/* When creating temporary files, use this prefix
	   (to avoid conflicts with existing files). */
	const char *temp_file_prefix;
	/* If the backend needs to do DNS lookups, use this dns_client for
	   them. */
	struct dns_client *dns_client;

	/* Parent event to use, unless overridden by
	   fs_file_init_with_event() */
	struct event *event;

	/* Enable debugging */
	bool debug;
	/* Enable timing statistics */
	bool enable_timing;
};

struct fs_stats {
	/* Number of fs_prefetch() calls. Counted only if fs_read*() hasn't
	   already been called for the file (which would be pretty pointless
	   to do). */
	unsigned int prefetch_count;
	/* Number of fs_read*() calls. Counted only if fs_prefetch() hasn't
	   already been called for the file. */
	unsigned int read_count;
	/* Number of fs_lookup_metadata() calls. Counted only if neither
	   fs_read*() nor fs_prefetch() has been called for the file. */
	unsigned int lookup_metadata_count;
	/* Number of fs_stat() calls. Counted only if none of the above
	   has been called (because the stat result should be cached). */
	unsigned int stat_count;

	/* Number of fs_write*() calls. */
	unsigned int write_count;
	/* Number of fs_exists() calls, which actually went to the backend
	   instead of being handled by fs_stat() call due to fs_exists() not
	   being implemented. */
	unsigned int exists_count;
	/* Number of fs_delete() calls. */
	unsigned int delete_count;
	/* Number of fs_copy() calls. If backend doesn't implement copying
	   operation but falls back to regular read+write instead, this count
	   isn't increased but the read+write counters are. */
	unsigned int copy_count;
	/* Number of fs_rename() calls. */
	unsigned int rename_count;
	/* Number of fs_iter_init() calls. */
	unsigned int iter_count;

	/* Number of bytes written by fs_write*() calls. */
	uint64_t write_bytes;

	/* Cumulative sum of usecs spent on calls - set only if
	   fs_settings.enable_timing=TRUE */
	struct stats_dist *timings[FS_OP_COUNT];
};

struct fs_metadata {
	const char *key;
	const char *value;
};
ARRAY_DEFINE_TYPE(fs_metadata, struct fs_metadata);

typedef void fs_file_async_callback_t(void *context);

int fs_init(const char *driver, const char *args,
	    const struct fs_settings *set,
	    struct fs **fs_r, const char **error_r);
/* helper for fs_init, accepts a filesystem string
   that can come directly from config */
int fs_init_from_string(const char *str, const struct fs_settings *set,
			struct fs **fs_r, const char **error_r);
/* same as fs_unref() */
void fs_deinit(struct fs **fs);

void fs_ref(struct fs *fs);
void fs_unref(struct fs **fs);

/* Returns the parent filesystem (if this is a wrapper fs) or NULL if
   there's no parent. */
struct fs *fs_get_parent(struct fs *fs);
/* Returns the filesystem's driver name. */
const char *fs_get_driver(struct fs *fs);
/* Returns the root fs's driver name (bypassing all wrapper fses) */
const char *fs_get_root_driver(struct fs *fs);

struct fs_file *fs_file_init(struct fs *fs, const char *path, int mode_flags);
struct fs_file *fs_file_init_with_event(struct fs *fs, struct event *event,
					const char *path, int mode_flags);
void fs_file_deinit(struct fs_file **file);

/* If the file has an input streams open, close them. */
void fs_file_close(struct fs_file *file);

/* Return properties supported by backend. */
enum fs_properties fs_get_properties(struct fs *fs);

/* Add/replace metadata when saving a file. This makes sense only when the
   file is being created/replaced. */
void fs_set_metadata(struct fs_file *file, const char *key, const char *value);
/* Return file's all metadata. */
int fs_get_metadata(struct fs_file *file,
		    const ARRAY_TYPE(fs_metadata) **metadata_r);
/* Wrapper to fs_get_metadata() to lookup a specific key. Returns 1 if value_r
   is set, 0 if key wasn't found, -1 if error. */
int fs_lookup_metadata(struct fs_file *file, const char *key,
		       const char **value_r);

/* Returns the path given to fs_open(). If file was opened with
   FS_OPEN_MODE_CREATE_UNIQUE_128 and the write has already finished,
   return the path including the generated filename. */
const char *fs_file_path(struct fs_file *file);
/* Returns the file's fs. */
struct fs *fs_file_fs(struct fs_file *file);
/* Returns the file's event. */
struct event *fs_file_event(struct fs_file *file);

/* Return the error message for the last failed operation. */
const char *fs_last_error(struct fs *fs);
/* Convenience function for the above. Errors aren't preserved across files. */
const char *fs_file_last_error(struct fs_file *file);

/* Try to asynchronously prefetch file into memory. Returns TRUE if file is
   already in memory (i.e. caller should handle this file before prefetching
   more), FALSE if not. The length is a hint of how much the caller expects
   to read, but it may be more or less (0=whole file). */
bool fs_prefetch(struct fs_file *file, uoff_t length);
/* Returns >0 if something was read, -1 if error (errno is set). */
ssize_t fs_read(struct fs_file *file, void *buf, size_t size);
/* Returns a stream for reading from file. Multiple streams can be opened,
   and caller must destroy the streams before closing the file. */
struct istream *fs_read_stream(struct fs_file *file, size_t max_buffer_size);

/* Returns 0 if ok, -1 if error (errno is set). Note: With CREATE/REPLACE mode
   files you can call fs_write() only once, the file creation is finished by it.
   CREATE can return EEXIST here, if the destination file was already created.
   With APPEND mode each fs_write() atomically appends the given data to
   file. */
int fs_write(struct fs_file *file, const void *data, size_t size);

/* Write to file via output stream. The stream will be destroyed by
   fs_write_stream_finish/abort. The returned ostream is already corked and
   it doesn't need to be uncorked. */
struct ostream *fs_write_stream(struct fs_file *file);
/* Finish writing via stream, calling also o_stream_flush() on the stream and
   handling any pending errors. The file will be created/replaced/appended only
   after this call, same as with fs_write(). Anything written to the stream
   won't be visible earlier. Returns 1 if ok, 0 if async write isn't finished
   yet (retry calling fs_write_stream_finish_async()), -1 if error */
int fs_write_stream_finish(struct fs_file *file, struct ostream **output);
int fs_write_stream_finish_async(struct fs_file *file);
/* Abort writing via stream. Anything written to the stream is discarded.
   o_stream_ignore_last_errors() is called on the output stream so the caller
   doesn't need to do it. This must not be called after
   fs_write_stream_finish(), i.e. it can't be used to abort a pending async
   write. */
void fs_write_stream_abort_error(struct fs_file *file, struct ostream **output, const char *error_fmt, ...) ATTR_FORMAT(3, 4);

/* Set a hash to the following write. The storage can then verify that the
   input data matches the specified hash, or fail if it doesn't. Typically
   implemented by Content-MD5 header. */
void fs_write_set_hash(struct fs_file *file, const struct hash_method *method,
		       const void *digest);

/* Call the specified callback whenever the file can be read/written to.
   May call the callback immediately. */
void fs_file_set_async_callback(struct fs_file *file,
				fs_file_async_callback_t *callback,
				void *context);
/* Wait until some file can be read/written to more before returning.
   It's an error to call this when there are no pending async operations. */
void fs_wait_async(struct fs *fs);
/* Switch the fs to the current ioloop. This can be used to do fs_wait_async()
   among other IO work. Returns TRUE if there is actually some work that can
   be waited on. */
bool fs_switch_ioloop(struct fs *fs) ATTR_NOWARN_UNUSED_RESULT;

/* Returns 1 if file exists, 0 if not, -1 if error occurred. */
int fs_exists(struct fs_file *file);
/* Delete a file. Returns 0 if file was actually deleted by us, -1 if error. */
int fs_delete(struct fs_file *file);

/* Returns 0 if ok, -1 if error occurred (e.g. errno=ENOENT).
   All fs backends may not support all stat fields. */
int fs_stat(struct fs_file *file, struct stat *st_r);
/* Get number of links to the file. This is the same as using fs_stat()'s
   st_nlinks field, except not all backends support returning it via fs_stat().
   Returns 0 if ok, -1 if error occurred. */
int fs_get_nlinks(struct fs_file *file, nlink_t *nlinks_r);
/* Copy an object with possibly updated metadata. Destination parent
   directories are created automatically. Returns 0 if ok, -1 if error
   occurred. */
int fs_copy(struct fs_file *src, struct fs_file *dest);
/* Try to finish asynchronous fs_copy(). Returns the same as fs_copy(). */
int fs_copy_finish_async(struct fs_file *dest);
/* Atomically rename a file. Destination parent directories are created
   automatically. Returns 0 if ok, -1 if error occurred. */
int fs_rename(struct fs_file *src, struct fs_file *dest);

/* Exclusively lock a file. If file is already locked, wait for it for given
   number of seconds (0 = fail immediately). Returns 1 if locked, 0 if wait
   timed out, -1 if error. */
int fs_lock(struct fs_file *file, unsigned int secs, struct fs_lock **lock_r);
void fs_unlock(struct fs_lock **lock);

/* Iterate through all files or directories in the given directory.
   Doesn't recurse to child directories. It's not an error to iterate a
   nonexistent directory. */
struct fs_iter *
fs_iter_init(struct fs *fs, const char *path, enum fs_iter_flags flags);
struct fs_iter *
fs_iter_init_with_event(struct fs *fs, struct event *event,
			const char *path, enum fs_iter_flags flags);
/* Returns 0 if ok, -1 if iteration failed. */
int fs_iter_deinit(struct fs_iter **iter, const char **error_r);
/* Returns the next filename. */
const char *fs_iter_next(struct fs_iter *iter);

/* For asynchronous iterations: Specify the callback that is called whenever
   there's more data available for reading. */
void fs_iter_set_async_callback(struct fs_iter *iter,
				fs_file_async_callback_t *callback,
				void *context);
/* For asynchronous iterations: If fs_iter_next() returns NULL, use this
   function to determine if you should wait for more data or finish up. */
bool fs_iter_have_more(struct fs_iter *iter);

/* Return the filesystem's fs_stats. Note that each wrapper filesystem keeps
   track of its own fs_stats calls. You can use fs_get_parent() to get to the
   filesystem whose stats you want to see. */
const struct fs_stats *fs_get_stats(struct fs *fs);

/* Helper functions to count number of usecs for read/write operations. */
uint64_t fs_stats_get_read_usecs(const struct fs_stats *stats);
uint64_t fs_stats_get_write_usecs(const struct fs_stats *stats);

#endif
