#ifndef __NFS_WORKAROUNDS_H
#define __NFS_WORKAROUNDS_H

struct stat;

/* When syscall fails with ESTALE error, how many times to try reopening the
   file and retrying the operation. */
#define NFS_ESTALE_RETRY_COUNT 10

/* open() with some NFS workarounds */
int nfs_safe_open(const char *path, int flags);
/* stat() with some NFS workarounds */
int nfs_safe_stat(const char *path, struct stat *buf);

#endif
