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
/* Same as link(), but handle UDP retries by stat()ing to see if the success
   reply just got lost. Assumes that oldpath's link count is initially 1. */
int nfs_safe_link(const char *oldpath, const char *newpath);

/* Flush attribute cache for given path. If flush_dir is TRUE, also the
   directory's cache is flushed. */
void nfs_flush_attr_cache(const char *path, bool flush_dir);
/* Flush attribute cache for given file descriptor.
   The given path is used only for logging. */
bool nfs_flush_attr_cache_fd(const char *path, int fd);
/* Flush read cache for given fd. lock_type must be set to the file's current
   fcntl locking state (F_UNLCK, F_RDLCK, F_WRLCK). Set just_locked=TRUE if the
   file was locked at the same time as read cache flush was wanted (to avoid
   re-locking the file unneededly). */
void nfs_flush_read_cache(const char *path, int fd,
			  int lock_type, bool just_locked);

#endif
