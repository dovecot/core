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

#include "lib.h"
#include "mmap-util.h"

#include <fcntl.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef HAVE_LINUX_MREMAP

#include <sys/mman.h>

/* MMAP_BASE_MOVE may be negative as well */
#if SSIZE_T_MAX >= LLONG_MAX
   /* 64bit or more */
#  define MMAP_BASE_MOVE (1024ULL*1024ULL*1024ULL*128ULL) /* 128GB */
#else
   /* 32bit most likely */
#  define MMAP_BASE_MOVE (1024UL*1024UL*128UL) /* 128M */
#endif

/* get it near 4kB which is the most common page size */
#define MAX_CHUNKS (4096 / 2 / sizeof(size_t) - 3)

#define MMAP_SIGNATURE 0xdeadbeef

#define PAGE_ALIGN(size) \
	(((size) + page_size) & ~(page_size-1))

struct movable_header {
	unsigned int signature;
	int chunks;
	size_t size;

	void *chunk_ptr[MAX_CHUNKS];
	size_t chunk_size[MAX_CHUNKS];
};

static int page_size = 0;
static int header_size = 0;
static void *movable_mmap_base = NULL;

static void movable_mmap_init(void)
{
	page_size = getpagesize();

	if (page_size >= header_size)
		header_size = page_size;
	else {
		header_size = sizeof(struct movable_header) + page_size -
			sizeof(struct movable_header) % page_size;
	}
}

static int anon_mmap_fixed(void *address, size_t length)
{
	void *base;

#ifdef MAP_ANONYMOUS
	base = mmap(address, length, PROT_READ | PROT_WRITE,
		    MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
	int fd;

	/* mmap()ing /dev/zero should be the same with some platforms */
	fd = open("/dev/zero", O_RDWR);
	if (fd == -1)
		i_fatal("Can't open /dev/zero for creating anonymous mmap");

	base = mmap(address, length, PROT_READ | PROT_WRITE,
		    MAP_FIXED | MAP_PRIVATE, fd, 0);

	(void)close(fd);
#endif

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
	int ret;

	if (header_size == 0)
		movable_mmap_init();

	/* we need extra page to store the pieces which construct
	   the full mmap. also allocate only page-aligned mmap sizes. */
	length += header_size;
	length = PAGE_ALIGN(length);

	if (movable_mmap_base == NULL) {
		/* this is fully guessing */
		movable_mmap_base = ((char *) mmap_anon) + MMAP_BASE_MOVE;
		movable_mmap_base = (char *) NULL +
			PAGE_ALIGN((size_t) (movable_mmap_base - NULL));
	}

	do {
		ret = anon_mmap_fixed(movable_mmap_base, length);
		hdr = movable_mmap_base;

		movable_mmap_base = (char *) movable_mmap_base +
			MMAP_BASE_MOVE;

	} while (ret == -1 && errno == EINVAL);

	if (ret == -1)
		return MAP_FAILED;

	/* initialize the header */
	hdr->signature = MMAP_SIGNATURE;
	hdr->chunks = 1;
	hdr->size = length;
	hdr->chunk_ptr[0] = hdr;
	hdr->chunk_size[0] = length;

	return (char *) hdr + header_size;
}

static void *remove_chunks(struct movable_header *hdr, size_t new_size)
{
	int i;

	for (i = hdr->chunks-1; i > 0; i--) {
		if (hdr->size - hdr->chunk_size[i] < new_size)
			break;

		if (munmap(hdr->chunk_ptr[i], hdr->chunk_size[i]) < 0)
			i_panic("munmap() failed: %m");

		hdr->size -= hdr->chunk_size[i];
		hdr->chunks--;
	}

	return (char *) hdr + header_size;
}

static void *move_chunks(struct movable_header *hdr, size_t new_size,
			 int maymove)
{
	unsigned char *new_base, *p;
	int i;

	if (!maymove) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	new_base = mmap_anon(new_size - header_size);
	if (new_base == MAP_FAILED)
		return MAP_FAILED;

	/* copy first chunk without header */
	memcpy(new_base, (char *) hdr->chunk_ptr[0] + header_size,
	       hdr->chunk_size[0] - header_size);
	p = new_base + (hdr->chunk_size[0] - header_size);

	for (i = 1; i < hdr->chunks; i++) {
		memcpy(p, hdr->chunk_ptr[i], hdr->chunk_size[i]);
		p += hdr->chunk_size[i];

		if (munmap(hdr->chunk_ptr[i], hdr->chunk_size[i]) < 0)
			i_panic("munmap() failed: %m");
	}

	if (munmap(hdr->chunk_ptr[0], hdr->chunk_size[0]) < 0)
		i_panic("munmap() failed: %m");
	return new_base;
}

static void *add_chunks(struct movable_header *hdr, size_t new_size,
			int maymove)
{
	void *base;
	size_t chunk_size;

	new_size = PAGE_ALIGN(new_size);
	if (hdr->chunks == MAX_CHUNKS)
		return move_chunks(hdr, new_size, maymove);

	/* get our new address, make sure we're not over/underflowing
	   our address */
#if MMAP_BASE_MOVE > 0
	base = (char *) hdr->chunk_ptr[hdr->chunks-1] +
		hdr->chunk_size[hdr->chunks-1];
	if (base < hdr->chunk_ptr[hdr->chunks-1])
		return move_chunks(hdr, new_size, maymove);
#else
	base = (char *) hdr->chunk_ptr[hdr->chunks-1] -
		hdr->chunk_size[hdr->chunks-1];
	if (base > hdr->chunk_ptr[hdr->chunks-1])
		return move_chunks(hdr, new_size, maymove);
#endif

	chunk_size = new_size - hdr->size;
	if (anon_mmap_fixed(base, chunk_size) < 0) {
		if (errno == EINVAL) {
			/* can't grow, the memory address is used */
			return move_chunks(hdr, new_size, maymove);
		}

		return MAP_FAILED;
	}

        hdr->chunk_ptr[hdr->chunks] = base;
	hdr->chunk_size[hdr->chunks] = chunk_size;
	hdr->size += chunk_size;
	hdr->chunks++;

	return (char *) hdr + header_size;
}

void *mremap_anon(void *old_address, size_t old_size  __attr_unused__,
		  size_t new_size, unsigned long flags)
{
	struct movable_header *hdr;

	if (old_address == NULL || old_address == MAP_FAILED) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	hdr = (struct movable_header *) ((char *) old_address - header_size);
	if (hdr->signature != MMAP_SIGNATURE)
		i_panic("movable_mremap(): Invalid old_address");

	new_size += header_size;

	if (hdr->size > new_size)
		return remove_chunks(hdr, new_size);
	else
		return add_chunks(hdr, new_size, (flags & MREMAP_MAYMOVE) != 0);
}

int munmap_anon(void *start, size_t length __attr_unused__)
{
	struct movable_header *hdr;
	int i;

	if (start == NULL || start == MAP_FAILED) {
		errno = EINVAL;
		return -1;
	}

	hdr = (struct movable_header *) ((char *) start - header_size);
	if (hdr->signature != MMAP_SIGNATURE)
		i_panic("movable_munmap(): Invalid address");

	/* [0] chunk must be free'd last since it contains the header */
	for (i = hdr->chunks-1; i >= 0; i--) {
		if (munmap(hdr->chunk_ptr[i], hdr->chunk_size[i]) < 0)
			i_panic("munmap() failed: %m");
	}

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
