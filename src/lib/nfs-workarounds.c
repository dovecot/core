/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

/*
   These tests were done with various Linux 2.6 kernels, FreeBSD 6.2 and
   Solaris 8 and 10.

   Attribute cache is usually flushed with chown()ing or fchown()ing the file.
   The safest way would be to use uid=-1 gid=-1, but this doesn't work with
   Linux (it does with FreeBSD 6.2 and Solaris). So we'll first get the
   file's owner and use it. As long as we're not root the file's owner can't
   change accidentally. If would be possible to also use chmod()/fchmod(), but
   that's riskier since it could actually cause an unwanted change.

   Write cache can be flushed with fdatasync(). It's all we need, but other
   tested alternatives are: fcntl locking (Linux 2.6, Solaris),
   fchown() (Solaris) and dup()+close() (Linux 2.6, Solaris).

   Read cache flushing is more problematic. There's no universal way to do it.
   The working methods are:

   Linux 2.6: fcntl(), O_DIRECT
   Solaris: fchown(), fcntl(), dup()+close()
   FreeBSD 6.2: fchown()

   fchown() can be easily used for Solaris and FreeBSD, but Linux requires
   playing with locks. O_DIRECT requires CONFIG_NFS_DIRECTIO to be enabled, so
   we can't always use it.
*/

#include "lib.h"
#include "nfs-workarounds.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if defined (__linux__) || defined(__sun)
#  define READ_CACHE_FLUSH_FCNTL
#endif
#if defined(__FreeBSD__) || defined(__sun)
#  define ATTRCACHE_FLUSH_CHOWN_UID_1
#endif

static int
nfs_safe_do(const char *path, int (*callback)(const char *path, void *context),
	    void *context)
{
        const char *dir = NULL;
        struct stat st;
        unsigned int i;
	int ret;

        t_push();
        for (i = 1;; i++) {
		ret = callback(path, context);
                if (ret == 0 || errno != ESTALE || i == NFS_ESTALE_RETRY_COUNT)
                        break;

                /* ESTALE: Some operating systems may fail with this if they
                   can't internally revalidating the NFS handle. It may also
                   happen if the parent directory has been deleted. If the
                   directory still exists, try reopening the file. */
                if (dir == NULL) {
                        dir = strrchr(path, '/');
                        if (dir == NULL)
                                break;
                        dir = t_strdup_until(path, dir);
		}
		nfs_flush_attr_cache_dir(path);
                if (stat(dir, &st) < 0) {
                        /* maybe it's gone or something else bad happened to
                           it. in any case we can't open the file, so fail
                           with the original ESTALE error and let our caller
                           handle it. */
                        errno = ESTALE;
                        break;
                }

                /* directory still exists, try reopening */
        }
        t_pop();
        return ret;
}

struct nfs_safe_open_context {
	int flags;
	int fd;
};

static int nfs_safe_open_callback(const char *path, void *context)
{
	struct nfs_safe_open_context *ctx = context;

	ctx->fd = open(path, ctx->flags);
	return ctx->fd == -1 ? -1 : 0;
}

int nfs_safe_open(const char *path, int flags)
{
	struct nfs_safe_open_context ctx;

        i_assert((flags & O_CREAT) == 0);

	ctx.flags = flags;
	if (nfs_safe_do(path, nfs_safe_open_callback, &ctx) < 0)
		return -1;

	return ctx.fd;
}

static int nfs_safe_stat_callback(const char *path, void *context)
{
	struct stat *buf = context;

	return stat(path, buf);
}

int nfs_safe_stat(const char *path, struct stat *buf)
{
	return nfs_safe_do(path, nfs_safe_stat_callback, buf);
}

static int nfs_safe_lstat_callback(const char *path, void *context)
{
	struct stat *buf = context;

	return lstat(path, buf);
}

int nfs_safe_lstat(const char *path, struct stat *buf)
{
	return nfs_safe_do(path, nfs_safe_lstat_callback, buf);
}

int nfs_safe_link(const char *oldpath, const char *newpath, bool links1)
{
	struct stat st;
	nlink_t orig_link_count = 1;

	if (!links1) {
		if (stat(oldpath, &st) < 0)
			return -1;
		orig_link_count = st.st_nlink;
	}

	if (link(oldpath, newpath) == 0) {
#ifndef __FreeBSD__
		return 0;
#endif
		/* FreeBSD at least up to v6.2 converts EEXIST errors to
		   success. */
	} else if (errno != EEXIST)
		return -1;

	/* We don't know if it succeeded or failed. stat() to make sure. */
	if (stat(oldpath, &st) < 0)
		return -1;
	if (st.st_nlink == orig_link_count) {
		errno = EEXIST;
		return -1;
	}
	return 0;
}

static void nfs_flush_chown_uid(const char *path)
{
	uid_t uid;

#ifdef ATTRCACHE_FLUSH_CHOWN_UID_1
	uid = (uid_t)-1;
#else
	struct stat st;

	if (stat(path, &st) == 0)
		uid = st.st_uid;
	else {
		if (errno == ESTALE) {
			/* ESTALE causes the OS to flush the attr cache */
			return;
		}
		if (errno != ENOENT) {
			i_error("nfs_flush_chown_uid: stat(%s) failed: %m",
				path);
			return;
		}

		/* flush a negative cache entry. use effective UID to chown.
		   it probably doesn't really matter what UID is used, because
		   as long as we're not root we don't have permission to really
		   change it anyway */
		uid = geteuid();
	}
#endif
	if (chown(path, uid, (gid_t)-1) < 0) {
		if (errno == ESTALE || errno == EACCES ||
		    errno == EPERM || errno == ENOENT) {
			/* attr cache is flushed */
			return;
		}
		i_error("nfs_flush_chown_uid: chown(%s) failed: %m", path);
	}
}

#ifdef READ_CACHE_FLUSH_FCNTL
static void nfs_flush_fcntl(const char *path, int fd)
{
	struct flock fl;
	int ret;

	/* If the file was already locked, we'll just get the same lock
	   again. It should succeed just fine. If was was unlocked, we'll
	   have to get a lock and then unlock it. Linux 2.6 flushes read cache
	   only when read/write locking succeeded. */
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	alarm(60);
	ret = fcntl(fd, F_SETLKW, &fl);
	alarm(0);

	if (unlikely(ret < 0)) {
		i_error("nfs_flush_fcntl: fcntl(%s, F_RDLCK) failed: %m", path);
		return;
	}

	fl.l_type = F_UNLCK;
	(void)fcntl(fd, F_SETLKW, &fl);
}
#endif

static void nfs_flush_attr_cache_parent_dir(const char *path)
{
	const char *p;

	p = strrchr(path, '/');
	if (p == NULL)
		nfs_flush_attr_cache_dir(".");
	else {
		t_push();
		nfs_flush_attr_cache_dir(t_strdup_until(path, p));
		t_pop();
	}
}

void nfs_flush_attr_cache_unlocked(const char *path)
{
#ifndef __FreeBSD__
	int fd;

	fd = open(path, O_RDONLY);
	if (fd != -1)
		(void)close(fd);
	else if (errno == ESTALE) {
		/* this already flushed the cache */
	} else
#endif
	{
		/* most likely ENOENT, which means a negative cache hit.
		   flush the parent directory's attribute cache. */
		nfs_flush_attr_cache_parent_dir(path);
	}
}

void nfs_flush_attr_cache_maybe_locked(const char *path)
{
	/* first we'll flush the parent directory to get the file handle
	   cache flushed */
	nfs_flush_attr_cache_parent_dir(path);

	/* after we now know the latest file handle, flush its attribute
	   cache */
	nfs_flush_chown_uid(path);
}

bool nfs_flush_attr_cache_fd_locked(const char *path ATTR_UNUSED,
				    int fd ATTR_UNUSED)
{
#ifdef __FreeBSD__
	if (fchown(fd, (uid_t)-1, (gid_t)-1) < 0) {
		if (errno == ESTALE)
			return FALSE;
		if (likely(errno == EACCES || errno == EPERM)) {
			/* attr cache is flushed */
			return TRUE;
		}

		i_error("nfs_flush_attr_cache_fd_locked: fchown(%s) failed: %m",
			path);
	}
	return TRUE;
#else
	return TRUE;
#endif
}

void nfs_flush_attr_cache_dir(const char *path)
{
#ifdef __FreeBSD__
	/* Unfortunately rmdir() seems to be the only way to flush a
	   directory's attribute cache. */
	if (unlikely(rmdir(path) == 0)) {
		if (mkdir(path, 0600) == 0) {
			i_warning("nfs_flush_dir: rmdir(%s) unexpectedly "
				  "removed the dir. recreated.", path);
		} else {
			i_error("nfs_flush_dir: rmdir(%s) unexpectedly "
				"removed the dir. mkdir() failed: %m", path);
		}
	} else if (likely(errno == ESTALE || errno == ENOENT ||
			  errno == ENOTEMPTY)) {
		/* expected failures */
	} else {
		i_error("nfs_flush_dir: rmdir(%s) failed: %m", path);
	}
#else
	int fd;

	fd = open(path, O_RDONLY);
	if (fd != -1)
		(void)close(fd);
#endif
}

void nfs_flush_read_cache_locked(const char *path ATTR_UNUSED,
				 int fd ATTR_UNUSED)
{
#ifdef READ_CACHE_FLUSH_FCNTL
	/* already flushed when fcntl() was called */
#else
	/* we can only hope that underlying filesystem uses micro/nanosecond
	   resolution so that attribute cache flushing notices mtime changes */
	nfs_flush_attr_cache_fd_locked(path, fd);
#endif
}

void nfs_flush_read_cache_unlocked(const char *path, int fd)
{
#ifdef READ_CACHE_FLUSH_FCNTL
	nfs_flush_fcntl(path, fd);
#else
	nfs_flush_read_cache_locked(path, fd);
#endif
}
