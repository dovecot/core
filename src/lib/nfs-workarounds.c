/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

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
#include "path-util.h"
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

static void nfs_flush_file_handle_cache_parent_dir(const char *path);

static int
nfs_safe_do(const char *path, int (*callback)(const char *path, void *context),
	    void *context)
{
        unsigned int i;
	int ret;

        for (i = 1;; i++) {
		ret = callback(path, context);
                if (ret == 0 || errno != ESTALE || i == NFS_ESTALE_RETRY_COUNT)
                        break;

                /* ESTALE: Some operating systems may fail with this if they
		   can't internally revalidate the NFS file handle. Flush the
		   file handle and try again */
		nfs_flush_file_handle_cache(path);
        }
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

#ifdef ATTRCACHE_FLUSH_CHOWN_UID_1
	uid_t uid = (uid_t)-1;
	if (chown(path, uid, (gid_t)-1) < 0) {
		if (errno == ESTALE || errno == EPERM || errno == ENOENT) {
			/* attr cache is flushed */
			return;
		}
		if (likely(errno == ENOENT)) {
			nfs_flush_file_handle_cache_parent_dir(path);
			return;
		}
		i_error("nfs_flush_chown_uid: chown(%s) failed: %m", path);
	}
#else
	struct stat st;

	if (stat(path, &st) == 0) {
		/* do nothing */
	} else {
		if (errno == ESTALE) {
			/* ESTALE causes the OS to flush the attr cache */
			return;
		}
		if (likely(errno == ENOENT)) {
			nfs_flush_file_handle_cache_parent_dir(path);
			return;
		}
		i_error("nfs_flush_chown_uid: stat(%s) failed: %m", path);
		return;
	}
	/* we use chmod for this operation since chown has been seen to drop S_UID
	   and S_GID bits from directory inodes in certain conditions */
	if (chmod(path, st.st_mode & 07777) < 0) {
		if (errno == EPERM) {
			/* attr cache is flushed */
			return;
		}
		if (likely(errno == ENOENT)) {
			nfs_flush_file_handle_cache_parent_dir(path);
			return;
		}
		i_error("nfs_flush_chown_uid: chmod(%s, %04o) failed: %m",
				path, st.st_mode & 07777);
	}
#endif
}

#ifdef __FreeBSD__
static bool nfs_flush_fchown_uid(const char *path, int fd)
{
	uid_t uid;
#ifndef ATTRCACHE_FLUSH_CHOWN_UID_1
	struct stat st;

	if (fstat(fd, &st) < 0) {
		if (likely(errno == ESTALE))
			return FALSE;
		i_error("nfs_flush_attr_cache_fchown: fstat(%s) failed: %m",
			path);
		return TRUE;
	}
	uid = st.st_uid;
#else
	uid = (uid_t)-1;
#endif
	if (fchown(fd, uid, (gid_t)-1) < 0) {
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
}
#endif

#ifdef READ_CACHE_FLUSH_FCNTL
static bool nfs_flush_fcntl(const char *path, int fd)
{
	static bool locks_disabled = FALSE;
	struct flock fl;
	int ret;

	if (locks_disabled)
		return FALSE;

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
		if (errno == ENOLCK) {
			locks_disabled = TRUE;
			return FALSE;
		}
		i_error("nfs_flush_fcntl: fcntl(%s, F_RDLCK) failed: %m", path);
		return FALSE;
	}

	fl.l_type = F_UNLCK;
	(void)fcntl(fd, F_SETLKW, &fl);
	return TRUE;
}
#endif

void nfs_flush_attr_cache_unlocked(const char *path)
{
	int fd;

	/* Try to flush the attribute cache the nice way first. */
	fd = open(path, O_RDONLY);
	if (fd != -1)
		i_close_fd(&fd);
	else if (errno == ESTALE) {
		/* this already flushed the cache */
	} else {
		/* most likely ENOENT, which means a negative cache hit.
		   flush the file handles for its parent directory. */
		nfs_flush_file_handle_cache_parent_dir(path);
	}
}

void nfs_flush_attr_cache_maybe_locked(const char *path)
{
	nfs_flush_chown_uid(path);
}

void nfs_flush_attr_cache_fd_locked(const char *path ATTR_UNUSED,
				    int fd ATTR_UNUSED)
{
#ifdef __FreeBSD__
	/* FreeBSD doesn't flush attribute cache with fcntl(), so we have
	   to do it ourself. */
	(void)nfs_flush_fchown_uid(path, fd);
#else
	/* Linux and Solaris are fine. */
#endif
}

static bool
nfs_flush_file_handle_cache_dir(const char *path, bool try_parent ATTR_UNUSED)
{
#ifdef __linux__
	/* chown()ing parent is the safest way to handle this */
	nfs_flush_chown_uid(path);
#else
	/* rmdir() is the only choice with FreeBSD and Solaris */
	if (unlikely(rmdir(path) == 0)) {
		if (mkdir(path, 0700) == 0) {
			i_warning("nfs_flush_file_handle_cache_dir: "
				  "rmdir(%s) unexpectedly "
				  "removed the dir. recreated.", path);
		} else {
			i_warning("nfs_flush_file_handle_cache_dir: "
				  "rmdir(%s) unexpectedly "
				  "removed the dir. mkdir() failed: %m", path);
		}
	} else if (errno == ESTALE || errno == ENOTDIR ||
		   errno == ENOTEMPTY || errno == EEXIST || errno == EACCES) {
		/* expected failures */
	} else if (errno == ENOENT) {
		return FALSE;
	} else if (errno == EINVAL && try_parent) {
		/* Solaris gives this if we're trying to rmdir() the current
		   directory. Work around this by temporarily changing the
		   current directory to the parent directory. */
		const char *cur_path, *p;
		int cur_dir_fd;
		bool ret;

		cur_dir_fd = open(".", O_RDONLY);
		if (cur_dir_fd == -1) {
			i_error("open(.) failed for: %m");
			return TRUE;
		}

		const char *error;
		if (t_get_working_dir(&cur_path, &error) < 0) {
			i_error("nfs_flush_file_handle_cache_dir: %s", error);
			i_close_fd(&cur_dir_fd);
			return TRUE;
		}
		p = strrchr(cur_path, '/');
		if (p == NULL)
			cur_path = "/";
		else
			cur_path = t_strdup_until(cur_path, p);
		if (chdir(cur_path) < 0) {
			i_error("nfs_flush_file_handle_cache_dir: "
				"chdir() failed");
		}
		ret = nfs_flush_file_handle_cache_dir(path, FALSE);
		if (fchdir(cur_dir_fd) < 0)
			i_error("fchdir() failed: %m");
		i_close_fd(&cur_dir_fd);
		return ret;
	} else {
		i_error("nfs_flush_file_handle_cache_dir: "
			"rmdir(%s) failed: %m", path);
	}
#endif
	return TRUE;
}

static void nfs_flush_file_handle_cache_parent_dir(const char *path)
{
	const char *p;

	p = strrchr(path, '/');
	T_BEGIN {
		if (p == NULL)
			(void)nfs_flush_file_handle_cache_dir(".", TRUE);
		else
			(void)nfs_flush_file_handle_cache_dir(t_strdup_until(path, p),
							      TRUE);
	} T_END;
}

void nfs_flush_file_handle_cache(const char *path)
{
	nfs_flush_file_handle_cache_parent_dir(path);
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
	if (!nfs_flush_fcntl(path, fd))
		nfs_flush_attr_cache_fd_locked(path, fd);
#else
	nfs_flush_read_cache_locked(path, fd);
#endif
}
