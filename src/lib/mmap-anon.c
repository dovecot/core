/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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

/* MMAP_BASE_MOVE may be set to negative as well */
#if SSIZE_T_MAX > 2147483647L
   /* 64bit or more */
#  define MMAP_BASE_MOVE (1024ULL*1024ULL*1024ULL*128ULL) /* 128GB */
#else
   /* 32bit most likely */
#  define MMAP_BASE_MOVE (1024UL*1024UL*128UL) /* 128M */
#endif

#define MMAP_SIGNATURE 0xdeadbeef

#define PAGE_ALIGN(size) \
	(((size) + (size_t)page_size-1) & ~(size_t)(page_size-1))

struct movable_header {
	unsigned int signature;
	size_t size;
};

static int page_size = 0;
static int header_size = 0;
static void *movable_mmap_base = NULL;
static void *mmap_top_limit, *mmap_heap_bottom, *mmap_heap_top;
static int zero_fd = -1;

static void movable_mmap_init(void)
{
	ssize_t abs_base_move;
	char x;

#if MAP_ANONYMOUS == 0
	/* mmap()ing /dev/zero should be the same with some platforms */
	zero_fd = open("/dev/zero", O_RDWR);
	if (zero_fd == -1)
		i_fatal("Can't open /dev/zero for creating anonymous mmap");
	fd_close_on_exec(zero_fd, TRUE);
#endif

	abs_base_move = MMAP_BASE_MOVE;
	if (abs_base_move < 0)
                abs_base_move = -abs_base_move;

	page_size = getpagesize();
	header_size = page_size;

	/* keep our allocations far below stack. assumes the stack is
	   growing down. */
	mmap_top_limit = &x - abs_base_move*2;

	/* keep our allocations far from heap */
	mmap_heap_bottom = malloc(1);
	mmap_heap_top = (char *) mmap_heap_bottom + abs_base_move*2;
	free(mmap_heap_bottom);
}

static int anon_mmap_fixed(void *address, size_t length)
{
	void *base;

	i_assert(address != NULL);

	base = mmap(address, length, PROT_READ | PROT_WRITE,
		    MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, zero_fd, 0);

	if (base != MAP_FAILED && base != address) {
		/* shouldn't happen with MAP_FIXED, but who knows.. */
		if (munmap(base, length) < 0)
			i_panic("munmap() failed: %m");
		base = MAP_FAILED;
		errno = EINVAL;
	}

	return base == MAP_FAILED ? -1 : 0;
}

void *mmap_anon(size_t length)
{
	struct movable_header *hdr;
	void *next_mmap_base, *base;
	ssize_t offset;
	unsigned int count;
	int ret;

	if (header_size == 0)
		movable_mmap_init();

	/* we need extra page to store the pieces which construct
	   the full mmap. also allocate only page-aligned mmap sizes. */
	length = PAGE_ALIGN(length + header_size);

	if (movable_mmap_base == NULL) {
		/* this is fully guessing */
		movable_mmap_base = (char *) NULL +
			PAGE_ALIGN((size_t)((char *)mmap_anon - (char *)NULL));
	}

	offset = MMAP_BASE_MOVE; count = 0;
	for (;;) {
		next_mmap_base = (char *) movable_mmap_base + offset;
		if ((char *) next_mmap_base < (char *) movable_mmap_base) {
			/* we're wrapping, fix the offset a bit so we won't
			   just loop with same addresses.. */
			offset /= 2;
			if (offset/10 < page_size) {
				/* enough tries */
				errno = ENOMEM;
				return MAP_FAILED;
			}
		}

		movable_mmap_base = next_mmap_base;

		if ((char *) movable_mmap_base >
		    (char *) movable_mmap_base + length) {
			/* too high, would wrap */
			continue;
		}

		if ((char *) movable_mmap_base + length >=
		    (char *) mmap_top_limit) {
			/* too high, stack could grow over it */
			continue;
		}

		if ((char *) movable_mmap_base >= (char *) mmap_heap_bottom &&
		    (char *) movable_mmap_base < (char *) mmap_heap_top) {
			/* too near heap */
			continue;
		}

		if (movable_mmap_base == NULL)
			continue;

		ret = anon_mmap_fixed(movable_mmap_base, length);
		if (ret == 0)
			break;

		if (errno != EINVAL && errno != ENOMEM)
			return MAP_FAILED;

		if (++count == 100) {
			/* enough tries, try non-fixed mmap() */
			base = mmap(NULL, length, PROT_READ | PROT_WRITE,
				    MAP_ANONYMOUS | MAP_PRIVATE, zero_fd, 0);
			if (base == MAP_FAILED)
				return MAP_FAILED;

			movable_mmap_base = base;
			break;
		}
	}

	/* initialize the header */
	hdr = movable_mmap_base;
	hdr->signature = MMAP_SIGNATURE;
	hdr->size = length - header_size;

	return (char *) hdr + header_size;
}

static int mremap_try_grow(struct movable_header *hdr, size_t new_size)
{
	void *grow_base;

	grow_base = (char *) hdr + header_size + hdr->size;
	if ((char *) grow_base <= (char *) hdr + header_size ||
	    (char *) grow_base >= (char *) mmap_top_limit) {
		/* overflows valid address range */
		return 0;
	}

	if (anon_mmap_fixed(grow_base, new_size - hdr->size) < 0) {
		if (errno == EINVAL || errno == ENOMEM) {
			/* can't grow, wanted address space is already in use */
			return 0;
		}

		return -1;
	}

	hdr->size = new_size;
	return 1;
}

static void *mremap_move(struct movable_header *hdr, size_t new_size)
{
	void *new_base;
	char *p;
	size_t block_size, old_size;

	new_base = mmap_anon(new_size - header_size);
	if (new_base == MAP_FAILED)
		return MAP_FAILED;

	/* If we're moving large memory areas, it takes less memory to
	   copy the memory pages in smaller blocks. */
	old_size = hdr->size;
	block_size = 1024*1024;

	p = (char *) (hdr + header_size + hdr->size);
	do {
		if (block_size > old_size)
			block_size = old_size;
		p -= block_size;

		memcpy((char *) new_base + (p - (char *) hdr), p, block_size);
		if (munmap((void *) p, block_size) < 0)
			i_panic("munmap() failed: %m");
	} while (p != (char *) hdr);

	return new_base;
}

void *mremap_anon(void *old_address, size_t old_size  __attr_unused__,
		  size_t new_size, unsigned long flags)
{
	struct movable_header *hdr;
	int ret;

	if (old_address == NULL || old_address == MAP_FAILED) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	hdr = (struct movable_header *) ((char *) old_address - header_size);
	if (hdr->signature != MMAP_SIGNATURE)
		i_panic("movable_mremap(): Invalid old_address");

	new_size = PAGE_ALIGN(new_size);

	if (new_size > hdr->size) {
		/* grow */
		ret = mremap_try_grow(hdr, new_size);
		if (ret > 0)
			return old_address;
		if (ret < 0)
			return MAP_FAILED;

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

int munmap_anon(void *start, size_t length __attr_unused__)
{
	struct movable_header *hdr;

	if (start == NULL || start == MAP_FAILED) {
		errno = EINVAL;
		return -1;
	}

	hdr = (struct movable_header *) ((char *) start - header_size);
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
