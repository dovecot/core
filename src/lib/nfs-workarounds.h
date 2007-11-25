#ifndef NFS_WORKAROUNDS_H
#define NFS_WORKAROUNDS_H

/* Note that some systems (Solaris) may use a macro to redefine struct stat */
#include <sys/stat.h>

/* When syscall fails with ESTALE error, how many times to try reopening the
   file and retrying the operation. */
#define NFS_ESTALE_RETRY_COUNT 10

/* Same as open(), but try to handle ESTALE errors. */
int nfs_safe_open(const char *path, int flags);
/* Same as stat(), but try to handle ESTALE errors.
   Doesn't flush attribute cache. */
int nfs_safe_stat(const char *path, struct stat *buf);
int nfs_safe_lstat(const char *path, struct stat *buf);
/* Same as link(), but handle problems with link() by verifying the file's
   link count changes. If links1=TRUE, assume the original file's link count
   is 1, otherwise stat() first to find it out. */
int nfs_safe_link(const char *oldpath, const char *newpath, bool links1);

/* Flush attribute cache for given path. The file must not be fcntl locked or
   the locks may get dropped. */
void nfs_flush_attr_cache_unlocked(const char *path);
/* Flush attribute cache for given path. The file may be fcntl locked. */
void nfs_flush_attr_cache_maybe_locked(const char *path);
/* Flush attribute cache for a fcntl locked file descriptor. If locking flushes
   the attribute cache with the running OS, this function does nothing.
   The given path is used only for logging. */
bool nfs_flush_attr_cache_fd_locked(const char *path, int fd);
/* Flush file handle cache for given file. */
void nfs_flush_file_handle_cache(const char *path);

/* Flush read cache for fd that was just fcntl locked. If the OS flushes
   read cache when fcntl locking file, this function does nothing. */
void nfs_flush_read_cache_locked(const char *path, int fd);
/* Flush read cache for fd that doesn't have fcntl locks. */
void nfs_flush_read_cache_unlocked(const char *path, int fd);

#endif
