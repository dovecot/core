/* Copyright (c) 2006 Timo Sirainen */

#include "lib.h"
#include "nfs-workarounds.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int nfs_safe_open(const char *path, int flags)
{
        const char *dir = NULL;
        struct stat st;
        unsigned int i;
        int fd;

        i_assert((flags & O_CREAT) == 0);

        t_push();
        for (i = 1;; i++) {
                fd = open(path, flags);
                if (fd != -1 || errno != ESTALE || i == NFS_ESTALE_RETRY_COUNT)
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
        return fd;
}
