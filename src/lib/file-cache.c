/* Copyright (c) 2004 Timo Sirainen */

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

void file_cache_free(struct file_cache *cache)
{
	if (cache->mmap_base != NULL) {
		if (munmap_anon(cache->mmap_base, cache->mmap_length) < 0)
			i_error("munmap_anon() failed: %m");
	}
	buffer_free(cache->page_bitmask);
	i_free(cache);
}

void file_cache_set_fd(struct file_cache *cache, int fd)
{
	cache->fd = fd;
	file_cache_invalidate(cache, 0, cache->mmap_length);
}

ssize_t file_cache_read(struct file_cache *cache, uoff_t offset, size_t size)
{
	size_t page_size = mmap_get_page_size();
	size_t poffset, psize, mmap_needed, dest_offset, dest_size;
	unsigned char *bits, *dest;
	ssize_t ret;

	i_assert(size < INT_MAX);

	if (offset + size > cache->mmap_length &&
	    offset + size - cache->mmap_length > 1024*1024) {
		/* growing more than a megabyte, make sure that the
		   file is large enough so we don't allocate memory
		   more than needed */
		struct stat st;

		if (fstat(cache->fd, &st) < 0) {
			i_error("fstat(file_cache) failed: %m");
			return -1;
		}

		if (offset + size > (uoff_t)st.st_size) {
			if (offset >= (uoff_t)st.st_size)
				return 0;
			size = (uoff_t)st.st_size - offset;
		}
	}

	poffset = offset / page_size;
	psize = (offset + size + page_size-1) / page_size - poffset;
	i_assert(psize > 0);

	mmap_needed = (poffset + psize) * page_size;
	if (mmap_needed > cache->mmap_length) {
		/* grow mmaping */
		if (cache->mmap_base == NULL) {
			cache->mmap_base = mmap_anon(mmap_needed);
			if (cache->mmap_base == MAP_FAILED) {
				i_error("mmap_anon(%"PRIuSIZE_T") failed: %m",
					mmap_needed);
				return -1;
			}
		} else {
			cache->mmap_base = mremap_anon(cache->mmap_base,
						       cache->mmap_length,
						       mmap_needed,
						       MREMAP_MAYMOVE);
			if (cache->mmap_base == MAP_FAILED) {
				i_error("mremap_anon(%"PRIuSIZE_T") failed: %m",
					mmap_needed);
				return -1;
			}
		}
		cache->mmap_length = mmap_needed;
	}

	bits = buffer_get_space_unsafe(cache->page_bitmask, poffset / CHAR_BIT,
				       (psize + CHAR_BIT - 1) / CHAR_BIT);

	dest_offset = poffset * page_size;
	dest = PTR_OFFSET(cache->mmap_base, dest_offset);
	dest_size = page_size;

	poffset %= CHAR_BIT;
	while (psize > 0) {
		if (bits[poffset / CHAR_BIT] & (1 << (poffset % CHAR_BIT))) {
			/* page is already in cache */
			psize--; poffset++;
			dest += page_size;
			dest_offset += page_size;
			continue;
		}

		ret = pread(cache->fd, dest, dest_size, dest_offset);
		if (ret <= 0) {
			if (ret < 0)
				return -1;

			/* EOF */
			/* FIXME: we should mark the last block cached and
			   invalidate it only when trying to read past the
			   file */
			return dest_offset <= offset ? 0 :
				dest_offset - offset < size ?
				dest_offset - offset : size;
		}

		dest += ret;
		dest_offset += ret;

		if (cache->read_highwater < dest_offset)
			cache->read_highwater = dest_offset;

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

void file_cache_invalidate(struct file_cache *cache, uoff_t offset, size_t size)
{
	size_t page_size = mmap_get_page_size();
	unsigned char *bits, mask;
	unsigned int i;

	if (offset >= cache->read_highwater)
		return;

	if (size > cache->read_highwater - offset)
		size = cache->read_highwater - offset;

	size = (offset + size + page_size-1) / page_size;
	offset /= page_size;
	size -= offset;

	bits = buffer_get_space_unsafe(cache->page_bitmask, offset / CHAR_BIT,
				       (size + CHAR_BIT - 1) / CHAR_BIT);

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
		mask = 0;
		for (i = 0, mask = 0; i < size; i++)
			mask |= 1 << i;
		*bits &= ~mask;
	}
}
