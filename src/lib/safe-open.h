#ifndef __SAFE_OPEN_H
#define __SAFE_OPEN_H

/* open() with some NFS workarounds */
int safe_open(const char *path, int flags);

#endif
