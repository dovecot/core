/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "mmap-util.h"
#include "file-cache.h"

#include <sys/stat.h>

struct file_cache {
	int fd;
	buffer_t *page_bitmask;

	void *mmap_base;
	size_t mmap_length;
	size_t read_highwater;
};

struct file_cache *file_cache_new(int fd)
{
	struct file_cache *cache;

	cache = i_new(struct file_cache, 1);
	cache->fd = fd;
	cache->page_bitmask = buffer_create_dynamic(default_pool, 128);
	return cache;
}

void file_cache_free(struct file_cache **_cache)
{
	struct file_cache *cache = *_cache;

	*_cache = NULL;

	if (cache->mmap_base != NULL) {
		if (munmap_anon(cache->mmap_base, cache->mmap_length) < 0)
			i_error("munmap_anon() failed: %m");
	}
	buffer_free(&cache->page_bitmask);
	i_free(cache);
}

void file_cache_set_fd(struct file_cache *cache, int fd)
{
	cache->fd = fd;
	file_cache_invalidate(cache, 0, cache->mmap_length);
}

int file_cache_set_size(struct file_cache *cache, uoff_t size)
{
	size_t page_size = mmap_get_page_size();
	uoff_t diff = size % page_size;
	void *new_base;

	if (diff != 0)
		size += page_size - diff;

	i_assert((size % page_size) == 0);
	if (size <= cache->mmap_length)
		return 0;

	if (size > (size_t)-1) {
		i_error("file_cache_set_size(%"PRIuUOFF_T"): size too large",
			size);
		return -1;
	}

	/* grow mmaping */
	if (cache->mmap_base == NULL) {
		cache->mmap_base = mmap_anon(size);
		if (cache->mmap_base == MAP_FAILED) {
			i_error("mmap_anon(%"PRIuUOFF_T") failed: %m", size);
			cache->mmap_length = 0;
			return -1;
		}
	} else {
		new_base = mremap_anon(cache->mmap_base, cache->mmap_length,
				       size, MREMAP_MAYMOVE);
		if (new_base == MAP_FAILED) {
			i_error("mremap_anon(%"PRIuUOFF_T") failed: %m", size);
			return -1;
		}

		cache->mmap_base = new_base;
	}
	cache->mmap_length = size;
	return 0;
}

ssize_t file_cache_read(struct file_cache *cache, uoff_t offset, size_t size)
{
	size_t page_size = mmap_get_page_size();
	size_t poffset, psize, dest_offset, dest_size;
	unsigned char *bits, *dest;
	ssize_t ret;

	if (size > SSIZE_T_MAX) {
		/* make sure our calculations won't overflow. most likely
		   we'll be reading less data, but allow it anyway so caller
		   doesn't have to deal with any extra checks. */
		size = SSIZE_T_MAX;
	}
	if (offset >= (uoff_t)-1 - size)
		size = (uoff_t)-1 - offset;

	if (offset + size > cache->mmap_length &&
	    offset + size - cache->mmap_length > 1024*1024) {
		/* growing more than a megabyte, make sure that the
		   file is large enough so we don't allocate memory
		   more than needed */
		struct stat st;

                if (fstat(cache->fd, &st) < 0) {
                        if (errno != ESTALE)
                                i_error("fstat(file_cache) failed: %m");
			return -1;
		}

		if (offset + size > (uoff_t)st.st_size) {
			if (offset >= (uoff_t)st.st_size)
				return 0;
			size = (uoff_t)st.st_size - offset;
		}
	}

	if (file_cache_set_size(cache, offset + size) < 0)
		return -1;

	poffset = offset / page_size;
	psize = (offset + size + page_size-1) / page_size - poffset;
	i_assert(psize > 0);

	bits = buffer_get_space_unsafe(cache->page_bitmask, 0,
				       (poffset + psize + CHAR_BIT - 1) /
				       CHAR_BIT);

	dest_offset = poffset * page_size;
	dest = PTR_OFFSET(cache->mmap_base, dest_offset);
	dest_size = page_size;

	while (psize > 0) {
		if (bits[poffset / CHAR_BIT] & (1 << (poffset % CHAR_BIT))) {
			/* page is already in cache */
			dest_offset += page_size;
			if (dest_offset <= cache->read_highwater) {
				psize--; poffset++;
				dest += page_size;
				continue;
			}

			/* this is the last partially cached block.
			   use the caching only if we don't want to
			   read past read_highwater */
			if (offset + size <= cache->read_highwater) {
				i_assert(psize == 1);
				break;
			}

			/* mark the block noncached again and
			   read it */
			bits[poffset / CHAR_BIT] &=
				~(1 << (poffset % CHAR_BIT));
			dest_offset -= page_size;
		}

		ret = pread(cache->fd, dest, dest_size, dest_offset);
		if (ret <= 0) {
			if (ret < 0)
				return -1;

			/* EOF. mark the last block as cached even if it
			   isn't completely. read_highwater tells us how far
			   we've actually made. */
			if (dest_offset == cache->read_highwater) {
				i_assert(poffset ==
					 cache->read_highwater / page_size);
				bits[poffset / CHAR_BIT] |=
					1 << (poffset % CHAR_BIT);
			}
			return dest_offset <= offset ? 0 :
				dest_offset - offset < size ?
				dest_offset - offset : size;
		}

		dest += ret;
		dest_offset += ret;

		if (cache->read_highwater < dest_offset) {
			unsigned int high_poffset =
				cache->read_highwater / page_size;

			/* read_highwater needs to be updated. if we didn't
			   just read that block, we can't trust anymore that
			   we have it cached */
			bits[high_poffset / CHAR_BIT] &=
				~(1 << (high_poffset % CHAR_BIT));
			cache->read_highwater = dest_offset;
		}

		if ((size_t)ret != dest_size) {
			/* partial read - probably EOF but make sure. */
			dest_size -= ret;
			continue;
		}

		bits[poffset / CHAR_BIT] |= 1 << (poffset % CHAR_BIT);
		dest_size = page_size;
		psize--; poffset++;
	}

	return size;
}

const void *file_cache_get_map(struct file_cache *cache, size_t *size_r)
{
	*size_r = cache->read_highwater;
	return cache->mmap_base;
}

void file_cache_write(struct file_cache *cache, const void *data, size_t size,
		      uoff_t offset)
{
	size_t page_size = mmap_get_page_size();
	unsigned char *bits;
	unsigned int first_page, last_page;

	i_assert((uoff_t)-1 - offset > size);

	if (file_cache_set_size(cache, offset + size) < 0) {
		/* couldn't grow mapping. just make sure the written memory
		   area is invalidated then. */
		file_cache_invalidate(cache, offset, size);
		return;
	}

	memcpy(PTR_OFFSET(cache->mmap_base, offset), data, size);

	if (cache->read_highwater < offset + size) {
		unsigned int page = cache->read_highwater / page_size;

		bits = buffer_get_space_unsafe(cache->page_bitmask,
					       page / CHAR_BIT, 1);
		*bits &= ~(1 << (page % CHAR_BIT));
		cache->read_highwater = offset + size;
	}

	/* mark fully written pages cached */
	if (size >= page_size) {
		first_page = offset / page_size;
		last_page = (offset + size) / page_size;
		if ((offset % page_size) != 0)
			first_page++;

		bits = buffer_get_space_unsafe(cache->page_bitmask, 0,
					       last_page / CHAR_BIT + 1);
		for (; first_page < last_page; first_page++) {
			bits[first_page / CHAR_BIT] |=
				1 << (first_page % CHAR_BIT);
		}
	}
}

void file_cache_invalidate(struct file_cache *cache, uoff_t offset, uoff_t size)
{
	size_t page_size = mmap_get_page_size();
	unsigned char *bits, mask;
	unsigned int i;

	if (offset >= cache->read_highwater || size == 0)
		return;

	if (size > cache->read_highwater - offset) {
		/* ignore anything after read highwater */
		size = cache->read_highwater - offset;
	}
	if (size >= cache->read_highwater) {
		/* we're invalidating everything up to read highwater.
		   drop the highwater position. */
		cache->read_highwater = offset & ~(page_size-1);
	}

	size = (offset + size + page_size-1) / page_size;
	offset /= page_size;
	i_assert(size > offset);
	size -= offset;

	if (size != 1) {
		/* tell operating system that we don't need the memory anymore
		   and it may free it. don't bother to do it for single pages,
		   there's a good chance that they get re-read back
		   immediately. */
		(void)madvise(PTR_OFFSET(cache->mmap_base, offset * page_size),
			      size * page_size, MADV_DONTNEED);
	}

	bits = buffer_get_space_unsafe(cache->page_bitmask, offset / CHAR_BIT,
				       1 + (size + CHAR_BIT - 1) / CHAR_BIT);

	/* set the first byte */
	for (i = offset % CHAR_BIT, mask = 0; i < CHAR_BIT && size > 0; i++) {
		mask |= 1 << i;
		size--;
	}
	*bits++ &= ~mask;

	/* set the middle bytes */
	memset(bits, 0, size / CHAR_BIT);
	bits += size / CHAR_BIT;
	size %= CHAR_BIT;

	/* set the last byte */
	if (size > 0) {
		for (i = 0, mask = 0; i < size; i++)
			mask |= 1 << i;
		*bits &= ~mask;
	}
}
