#ifndef FS_WRAPPER_H
#define FS_WRAPPER_H

enum fs_get_metadata_flags;

enum fs_properties fs_wrapper_get_properties(struct fs *fs);
void fs_wrapper_file_close(struct fs_file *file);
const char *fs_wrapper_file_get_path(struct fs_file *file);
void fs_wrapper_set_async_callback(struct fs_file *file,
				   fs_file_async_callback_t *callback,
				   void *context);
void fs_wrapper_wait_async(struct fs *fs);
void fs_wrapper_set_metadata(struct fs_file *file, const char *key,
			     const char *value);
int fs_wrapper_get_metadata(struct fs_file *file,
			    enum fs_get_metadata_flags flags,
			    const ARRAY_TYPE(fs_metadata) **metadata_r);
bool fs_wrapper_prefetch(struct fs_file *file, uoff_t length);
ssize_t fs_wrapper_read(struct fs_file *file, void *buf, size_t size);
struct istream *
fs_wrapper_read_stream(struct fs_file *file, size_t max_buffer_size);
int fs_wrapper_write(struct fs_file *file, const void *data, size_t size);
void fs_wrapper_write_stream(struct fs_file *file);
int fs_wrapper_write_stream_finish(struct fs_file *file, bool success);
int fs_wrapper_lock(struct fs_file *file, unsigned int secs,
		    struct fs_lock **lock_r);
void fs_wrapper_unlock(struct fs_lock *_lock);
int fs_wrapper_exists(struct fs_file *file);
int fs_wrapper_stat(struct fs_file *file, struct stat *st_r);
int fs_wrapper_get_nlinks(struct fs_file *file, nlink_t *nlinks_r);
int fs_wrapper_copy(struct fs_file *src, struct fs_file *dest);
int fs_wrapper_rename(struct fs_file *src, struct fs_file *dest);
int fs_wrapper_delete(struct fs_file *file);
struct fs_iter *fs_wrapper_iter_alloc(void);
void fs_wrapper_iter_init(struct fs_iter *iter, const char *path,
			  enum fs_iter_flags flags);
const char *fs_wrapper_iter_next(struct fs_iter *iter);
int fs_wrapper_iter_deinit(struct fs_iter *iter);

#endif
