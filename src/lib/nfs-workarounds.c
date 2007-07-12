/* Copyright (c) 2006 Timo Sirainen */

#include "lib.h"
#include "nfs-workarounds.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

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
