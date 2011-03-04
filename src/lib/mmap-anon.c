/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "mmap-util.h"

#include <fcntl.h>

#ifndef MAP_ANONYMOUS
#  ifdef MAP_ANON
#    define MAP_ANONYMOUS MAP_ANON
#  else
#    define MAP_ANONYMOUS 0
#  endif
#endif

#ifndef HAVE_LINUX_MREMAP

#include "fd-close-on-exec.h"

#include <stdlib.h>
#include <sys/mman.h>

#define MMAP_SIGNATURE 0xdeadbeef

#define PAGE_ALIGN(size) \
	(((size) + (size_t)page_size-1) & ~(size_t)(page_size-1))

struct anon_header {
	unsigned int signature;
	size_t size;
};

static int page_size = 0;
static int header_size = 0;
static int zero_fd = -1;

static void movable_mmap_init(void)
{
#if MAP_ANONYMOUS == 0
	/* mmap()ing /dev/zero should be the same with some platforms */
	zero_fd = open("/dev/zero", O_RDWR);
	if (zero_fd == -1)
		i_fatal("Can't open /dev/zero for creating anonymous mmap: %m");
	fd_close_on_exec(zero_fd, TRUE);
#endif

	page_size = getpagesize();
	header_size = page_size;
}

void *mmap_anon(size_t length)
{
	struct anon_header *hdr;
	void *base;

	if (header_size == 0)
		movable_mmap_init();

	/* we need extra page to store the pieces which construct
	   the full mmap. also allocate only page-aligned mmap sizes. */
	length = PAGE_ALIGN(length + header_size);

	base = mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, zero_fd, 0);
	if (base == MAP_FAILED)
		return MAP_FAILED;

	/* initialize the header */
	hdr = base;
	hdr->signature = MMAP_SIGNATURE;
	hdr->size = length - header_size;

	return (char *) hdr + header_size;
}

static void *mremap_move(struct anon_header *hdr, size_t new_size)
{
	void *new_base;
	char *p;
	size_t block_size, old_size;

	new_base = mmap_anon(new_size);
	if (new_base == MAP_FAILED)
		return MAP_FAILED;

	/* If we're moving large memory areas, it takes less memory to
	   copy the memory pages in smaller blocks. */
	old_size = hdr->size;
	block_size = 1024*1024;

	p = (char *) hdr + header_size + hdr->size;
	do {
		if (block_size > old_size)
			block_size = old_size;
		p -= block_size;
		old_size -= block_size;

		memcpy((char *) new_base + old_size, p, block_size);
		if (munmap((void *) p, block_size) < 0)
			i_panic("munmap() failed: %m");
	} while (old_size != 0);

	if (munmap((void *) hdr, header_size) < 0)
		i_panic("munmap() failed: %m");

	return new_base;
}

void *mremap_anon(void *old_address, size_t old_size  ATTR_UNUSED,
		  size_t new_size, unsigned long flags)
{
	struct anon_header *hdr;

	if (old_address == NULL || old_address == MAP_FAILED) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	hdr = (struct anon_header *) ((char *) old_address - header_size);
	if (hdr->signature != MMAP_SIGNATURE)
		i_panic("movable_mremap(): Invalid old_address");

	new_size = PAGE_ALIGN(new_size);

	if (new_size > hdr->size) {
		/* grow */
		if ((flags & MREMAP_MAYMOVE) == 0) {
			errno = ENOMEM;
			return MAP_FAILED;
		}

		return mremap_move(hdr, new_size);
	}

	if (new_size < hdr->size) {
		/* shrink */
		if (munmap((void *) ((char *) hdr + header_size + new_size),
			   hdr->size - new_size) < 0)
			i_panic("munmap() failed: %m");
		hdr->size = new_size;
	}

	return old_address;
}

int munmap_anon(void *start, size_t length ATTR_UNUSED)
{
	struct anon_header *hdr;

	if (start == NULL || start == MAP_FAILED) {
		errno = EINVAL;
		return -1;
	}

	hdr = (struct anon_header *) ((char *) start - header_size);
	if (hdr->signature != MMAP_SIGNATURE)
		i_panic("movable_munmap(): Invalid address");

	if (munmap((void *) hdr, hdr->size + header_size) < 0)
		i_panic("munmap() failed: %m");

	return 0;
}

#else

void *mmap_anon(size_t length)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
}

void *mremap_anon(void *old_address, size_t old_size, size_t new_size,
		  unsigned long flags)
{
	return mremap(old_address, old_size, new_size, flags);
}

int munmap_anon(void *start, size_t length)
{
	return munmap(start, length);
}

#endif
