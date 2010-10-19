#ifndef FS_API_H
#define FS_API_H

struct stat;
struct fs_file;
struct fs_lock;

enum fs_open_mode {
	/* Open only for reading, or fail with ENOENT if it doesn't exist */
	FS_OPEN_MODE_RDONLY,
	/* Create a new file, fail with EEXIST if it already exists */
	FS_OPEN_MODE_CREATE,
	/* Create or replace a file */
	FS_OPEN_MODE_REPLACE,
	/* Append to existing file, fail with ENOENT if it doesn't exist */
	FS_OPEN_MODE_APPEND

#define FS_OPEN_MODE_MASK 0x0f
};

enum fs_open_flags {
	/* Call fdatasync() on files after writes */
	FS_OPEN_FLAG_FDATASYNC	= 0x10,
	/* Create any missing parent directories for new files */
	FS_OPEN_FLAG_MKDIR	= 0x20
};

struct fs_settings {
	/* When creating temporary files, use this prefix
	   (to avoid conflicts with existing files). */
	const char *temp_file_prefix;
};

struct fs *fs_init(const char *driver, const char *args,
		   const struct fs_settings *set);
void fs_deinit(struct fs **fs);

/* Returns 0 if opened, -1 if error (errno is set). */
int fs_open(struct fs *fs, const char *path, int mode_flags,
	    struct fs_file **file_r);
void fs_close(struct fs_file **file);

/* Returns the path given to fs_open(). */
const char *fs_file_path(struct fs_file *file);

/* Return the error message for the last failed operation. */
const char *fs_last_error(struct fs *fs);
/* Convenience function for the above. Errors aren't preserved across files. */
const char *fs_file_last_error(struct fs_file *file);

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
   won't be visible earlier. */
int fs_write_stream_finish(struct fs_file *file, struct ostream **output);
/* Abort writing via stream. Anything written to the stream is discarded. */
void fs_write_stream_abort(struct fs_file *file, struct ostream **output);

/* Exclusively lock a file. If file is already locked, wait for it for given
   number of seconds (0 = fail immediately). Returns 1 if locked, 0 if wait
   timed out, -1 if error. */
int fs_lock(struct fs_file *file, unsigned int secs, struct fs_lock **lock_r);
void fs_unlock(struct fs_lock **lock);

/* Make sure all written data is flushed to disk. */
int fs_fdatasync(struct fs_file *file);

/* Returns 1 if file exists, 0 if not, -1 if error occurred. */
int fs_exists(struct fs *fs, const char *path);
/* Returns 0 if ok, -1 if error occurred (e.g. errno=ENOENT).
   All fs backends may not support all stat fields. */
int fs_stat(struct fs *fs, const char *path, struct stat *st_r);
/* Create a hard link. Destination parent directories are created
   automatically. Returns 0 if ok, -1 if error occurred
   (errno=EXDEV if hard links not supported by backend). */
int fs_link(struct fs *fs, const char *src, const char *dest);
/* Atomically rename a file. Destination parent directories are created
   automatically. Returns 0 if ok, -1 if error occurred
   (errno=EXDEV if hard links not supported by backend). */
int fs_rename(struct fs *fs, const char *src, const char *dest);
/* Unlink a file. */
int fs_unlink(struct fs *fs, const char *path);
/* Delete a directory. Returns 0 if ok, -1 if error occurred. */
int fs_rmdir(struct fs *fs, const char *path);

#endif
