#ifndef __MMAP_UTIL_H
#define __MMAP_UTIL_H

#include <unistd.h>
#include <sys/mman.h>

#ifndef HAVE_MADVISE
int madvise(void *start, size_t length, int advice);
#  ifndef MADV_NORMAL
#    define MADV_NORMAL 0
#    define MADV_RANDOM 0
#    define MADV_SEQUENTIAL 0
#    define MADV_WILLNEED 0
#    define MADV_DONTNEED 0
#  endif
#endif

void *mmap_ro_file(int fd, size_t *length);
void *mmap_rw_file(int fd, size_t *length);

void *mmap_aligned(int fd, int access, off_t offset, size_t length,
		   void **data_start, size_t *mmap_length);

void *mmap_anonymous(size_t length);

#endif
