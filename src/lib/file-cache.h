#ifndef __FILE_CACHE_H
#define __FILE_CACHE_H

/* Create a new file cache. It works very much like file-backed mmap()ed
   memory, but it works more nicely with remote filesystems (no SIGBUS). */
struct file_cache *file_cache_new(int fd);
void file_cache_free(struct file_cache *cache);

/* Change cached file descriptor. Invalidates the whole cache. */
void file_cache_set_fd(struct file_cache *cache, int fd);

/* Read data from file, returns how many bytes was actually read or -1 if
   error occured. */
ssize_t file_cache_read(struct file_cache *cache, uoff_t offset, size_t size);

/* Returns pointer to beginning of cached file. Only parts of the returned
   memory that are valid are the ones that have been file_cache_read().
   Note that the pointer may become invalid after calling file_cache_read(). */
const void *file_cache_get_map(struct file_cache *cache, size_t *size_r);

/* Invalidate cached memory area. It will be read again next time it's tried
   to be accessed. */
void file_cache_invalidate(struct file_cache *cache,
			   uoff_t offset, size_t size);

#endif
