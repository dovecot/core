#ifndef FS_API_H
#define FS_API_H

struct stat;
struct fs;
struct fs_file;
struct fs_lock;

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
	FS_PROPERTY_DIRECTORIES	= 0x80
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
	FS_OPEN_FLAG_SEEKABLE		= 0x40
};

enum fs_iter_flags {
	/* Iterate only directories, not files */
	FS_ITER_FLAG_DIRS	= 0x01
};

struct fs_settings {
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

	/* Enable debugging */
	bool debug;
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
void fs_deinit(struct fs **fs);

/* Returns the root fs's driver name (bypassing all wrapper fses) */
const char *fs_get_root_driver(struct fs *fs);

struct fs_file *fs_file_init(struct fs *fs, const char *path, int mode_flags);
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

/* Returns the path given to fs_open(). If file was opened with
   FS_OPEN_MODE_CREATE_UNIQUE_128 and the write has already finished,
   return the path including the generated filename. */
const char *fs_file_path(struct fs_file *file);

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
   fs_write_stream_finish/abort. */
struct ostream *fs_write_stream(struct fs_file *file);
/* Finish writing via stream. The file will be created/replaced/appended only
   after this call, same as with fs_write(). Anything written to the stream
   won't be visible earlier. Returns 1 if ok, 0 if async write isn't finished
   yet (retry calling fs_write_stream_finish_async()), -1 if error */
int fs_write_stream_finish(struct fs_file *file, struct ostream **output);
int fs_write_stream_finish_async(struct fs_file *file);
/* Abort writing via stream. Anything written to the stream is discarded. */
void fs_write_stream_abort(struct fs_file *file, struct ostream **output);

/* Call the specified callback whenever the file can be read/written to.
   May call the callback immediately. */
void fs_file_set_async_callback(struct fs_file *file,
				fs_file_async_callback_t *callback,
				void *context);
/* Wait until some file can be read/written to more before returning.
   It's an error to call this when there are no pending async operations.
   Returns 0 if ok, -1 if timed out. */
int fs_wait_async(struct fs *fs);

/* Returns 1 if file exists, 0 if not, -1 if error occurred. */
int fs_exists(struct fs_file *file);
/* Delete a file. Returns 0 if file was actually deleted by us, -1 if error. */
int fs_delete(struct fs_file *file);

/* Returns 0 if ok, -1 if error occurred (e.g. errno=ENOENT).
   All fs backends may not support all stat fields. */
int fs_stat(struct fs_file *file, struct stat *st_r);
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
/* Returns 0 if ok, -1 if iteration failed. */
int fs_iter_deinit(struct fs_iter **iter);
/* Returns the next filename. */
const char *fs_iter_next(struct fs_iter *iter);

#endif
