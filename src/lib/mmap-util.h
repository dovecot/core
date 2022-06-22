#ifndef MMAP_UTIL_H
#define MMAP_UTIL_H

#include <unistd.h>

#ifdef HAVE_LINUX_MREMAP
#  define __USE_GNU /* for MREMAP_MAYMOVE */
#endif

#include <sys/mman.h>
#undef __USE_GNU

#if !defined (MREMAP_MAYMOVE) && !defined (HAVE_LINUX_MREMAP)
#  define MREMAP_MAYMOVE 1
#endif

void *mmap_file(int fd, size_t *length, int prot);
void *mmap_ro_file(int fd, size_t *length);
void *mmap_rw_file(int fd, size_t *length);

/* for allocating anonymous mmap()s, with portable mremap(). these must not
   be mixed with any standard mmap calls. */
void *mmap_anon(size_t length);
void *mremap_anon(void *old_address, size_t old_size, size_t new_size,
		  unsigned long flags);
int munmap_anon(void *start, size_t length);

size_t mmap_get_page_size(void) ATTR_CONST;

#endif
