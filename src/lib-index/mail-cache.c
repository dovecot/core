/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-cache-private.h"

#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>

unsigned int mail_cache_field_sizes[32] = {
	sizeof(enum mail_cache_record_flag),
	sizeof(uoff_t),
	16,
	sizeof(struct mail_sent_date),
	sizeof(time_t),
	sizeof(uoff_t),
	sizeof(uoff_t),

	0, 0, 0, 0, 0,

	/* variable sized */
	(unsigned int)-1, (unsigned int)-1, (unsigned int)-1, (unsigned int)-1,
	(unsigned int)-1, (unsigned int)-1, (unsigned int)-1, (unsigned int)-1,
	(unsigned int)-1, (unsigned int)-1, (unsigned int)-1, (unsigned int)-1,
	(unsigned int)-1, (unsigned int)-1, (unsigned int)-1, (unsigned int)-1,
	(unsigned int)-1, (unsigned int)-1, (unsigned int)-1, (unsigned int)-1
};

enum mail_cache_field mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT] = {
	MAIL_CACHE_HEADERS1,
	MAIL_CACHE_HEADERS2,
	MAIL_CACHE_HEADERS3,
	MAIL_CACHE_HEADERS4
};

uint32_t mail_cache_uint32_to_offset(uint32_t offset)
{
	unsigned char buf[4];

	i_assert(offset < 0x40000000);
	i_assert((offset & 3) == 0);

	offset >>= 2;
	buf[0] = 0x80 | ((offset & 0x0fe00000) >> 21);
	buf[1] = 0x80 | ((offset & 0x001fc000) >> 14);
	buf[2] = 0x80 | ((offset & 0x00003f80) >> 7);
	buf[3] = 0x80 |  (offset & 0x0000007f);
	return *((uint32_t *) buf);
}

uint32_t mail_cache_offset_to_uint32(uint32_t offset)
{
	const unsigned char *buf = (const unsigned char *) &offset;

	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return (((uint32_t)buf[3] & 0x7f) << 2) |
		(((uint32_t)buf[2] & 0x7f) << 9) |
		(((uint32_t)buf[1] & 0x7f) << 16) |
		(((uint32_t)buf[0] & 0x7f) << 23);
}

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		cache->index->nodiskspace = TRUE;
		return;
	}

	mail_index_set_error(cache->index,
			     "%s failed with index cache file %s: %m",
			     function, cache->filepath);
}

void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
{
	va_list va;

        (void)mail_cache_reset(cache);

	if (cache->silent)
		return;

	va_start(va, fmt);
	t_push();
	mail_index_set_error(cache->index, "Corrupted index cache file %s: %s",
			     cache->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);
}

static void mail_cache_file_close(struct mail_cache *cache)
{
	if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	cache->mmap_base = NULL;
	cache->hdr = NULL;
	cache->mmap_length = 0;

	if (cache->fd != -1) {
		if (close(cache->fd) < 0)
			mail_cache_set_syscall_error(cache, "close()");
		cache->fd = -1;
	}
}

static int mail_cache_file_reopen(struct mail_cache *cache)
{
	int fd;

	fd = open(cache->filepath, O_RDWR);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	mail_cache_file_close(cache);

	cache->fd = fd;
	return 0;
}

static int mmap_verify_header(struct mail_cache *cache)
{
	struct mail_cache_header *hdr;
	uint32_t used_file_size;

	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "File too small");
		return 0;
	}
	cache->hdr = hdr = cache->mmap_base;

	if (cache->hdr->indexid != cache->index->indexid) {
		/* index id changed */
		if (cache->hdr->indexid != 0)
			mail_cache_set_corrupted(cache, "indexid changed");
		return 0;
	}

	if (cache->trans_ctx != NULL) {
		/* we've updated used_file_size, do nothing */
		return 1;
	}

	/* only check the header if we're locked */
	if (cache->locks == 0)
		return 1;

	used_file_size = nbo_to_uint32(hdr->used_file_size);
	if (used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return 0;
	}
	if ((used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return 0;
	}

	if (used_file_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "used_file_size too large");
		return 0;
	}
	return 1;
}

static int mmap_update_nocheck(struct mail_cache *cache,
			       size_t offset, size_t size)
{
	struct stat st;

#if 0 // FIXME
	/* if sequence has changed, the file has to be reopened.
	   note that if main index isn't locked, it may change again */
	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq &&
	    cache->mmap_base != NULL) {
		if (mail_cache_file_reopen(cache) < 0)
			return -1;
	}
#endif

	if (offset < cache->mmap_length &&
	    size <= cache->mmap_length - offset &&
	    !cache->mmap_refresh) {
		/* already mapped */
		if (size != 0)
			return 1;

		/* requesting the whole file - see if we need to
		   re-mmap */
		if (fstat(cache->fd, &st) < 0) {
			mail_cache_set_syscall_error(cache, "fstat()");
			return -1;
		}
		if ((uoff_t)st.st_size == cache->mmap_length)
			return 1;
	}
	cache->mmap_refresh = FALSE;

	if (cache->mmap_base != NULL) {
		if (cache->locks != 0) {
			/* in the middle of transaction - write the changes */
			if (msync(cache->mmap_base, cache->mmap_length,
				  MS_SYNC) < 0) {
				mail_cache_set_syscall_error(cache, "msync()");
				return -1;
			}
		}

		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	i_assert(cache->fd != -1);

	/* map the whole file */
	cache->hdr = NULL;
	cache->mmap_length = 0;

	cache->mmap_base = mmap_rw_file(cache->fd, &cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		cache->mmap_base = NULL;
		mail_cache_set_syscall_error(cache, "mmap()");
		return -1;
	}

	/* re-mmaped, check header */
	return 0;
}

int mail_cache_mmap_update(struct mail_cache *cache, size_t offset, size_t size)
{
	int synced, ret;

	for (synced = FALSE;; synced = TRUE) {
		ret = mmap_update_nocheck(cache, offset, size);
		if (ret > 0)
			return 0;
		if (ret < 0)
			return -1;

		if (mmap_verify_header(cache) <= 0)
			return -1;

#if 0 // FIXME
		/* see if cache file was rebuilt - do it only once to avoid
		   infinite looping */
		if (cache->hdr->file_seq == cache->index->hdr->cache_file_seq ||
		    synced)
			break;

		if (mail_cache_file_reopen(cache) < 0)
			return -1;
#endif
	}
	return 0;
}

static int mail_cache_open_and_verify(struct mail_cache *cache, int silent)
{
	struct stat st;
	int ret;

	mail_cache_file_close(cache);

	cache->fd = open(cache->filepath, O_RDWR);
	if (cache->fd == -1) {
		if (errno == ENOENT)
			return 0;

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	if (fstat(cache->fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		return -1;
	}

	if (st.st_size < sizeof(struct mail_cache_header))
		return 0;

	cache->mmap_refresh = TRUE;
	if (mmap_update_nocheck(cache, 0, sizeof(struct mail_cache_header)) < 0)
		return -1;

	/* verify that this really is the cache for wanted index */
	cache->silent = silent;
	if ((ret = mmap_verify_header(cache)) <= 0) {
		cache->silent = FALSE;
		return ret;
	}

	cache->silent = FALSE;
	return 1;
}

static int mail_cache_open_or_create_file(struct mail_cache *cache,
					  struct mail_cache_header *hdr)
{
	int ret, fd;

	cache->filepath = i_strconcat(cache->index->filepath,
				      MAIL_CACHE_FILE_PREFIX, NULL);

	ret = mail_cache_open_and_verify(cache, FALSE);
	if (ret != 0)
		return ret < 0 ? -1 : 0;

	/* maybe a rebuild.. */
	fd = file_dotlock_open(cache->filepath, NULL, NULL,
			       MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	/* see if someone else just created the cache file */
	ret = mail_cache_open_and_verify(cache, TRUE);
	if (ret != 0) {
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		return ret < 0 ? -1 : 0;
	}

	/* rebuild then */
	if (write_full(fd, hdr, sizeof(*hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		return -1;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		return -1;
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, NULL, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return -1;
	}

	if (mail_cache_mmap_update(cache, 0,
				   sizeof(struct mail_cache_header)) < 0)
		return -1;

	return 0;
}

struct mail_cache *mail_cache_open_or_create(struct mail_index *index)
{
        struct mail_cache_header hdr;
	struct mail_cache *cache;

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = index->indexid;
	hdr.file_seq = index->hdr->cache_file_seq + 1;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
        cache->split_header_pool = pool_alloconly_create("Headers", 512);

	if (mail_cache_open_or_create_file(cache, &hdr) < 0) {
		/* failed for some reason - doesn't really matter,
		   just disable caching. */
		mail_cache_file_close(cache);

		i_free(cache->filepath);
		cache->filepath = i_strdup_printf("(disabled cache for %s)",
						  index->filepath);
		cache->disabled = TRUE;
	}

	return cache;
}

void mail_cache_free(struct mail_cache *cache)
{
	i_assert(cache->trans_ctx == NULL);

	mail_cache_file_close(cache);

	pool_unref(cache->split_header_pool);
	i_free(cache->filepath);
	i_free(cache);
}

void mail_cache_set_defaults(struct mail_cache *cache,
			     enum mail_cache_field default_cache_fields,
			     enum mail_cache_field never_cache_fields)
{
	cache->default_cache_fields = default_cache_fields;
	cache->never_cache_fields = never_cache_fields;
}

int mail_cache_reset(struct mail_cache *cache)
{
	struct mail_cache_header hdr;
	int fd;

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = cache->index->indexid;
	hdr.file_seq = cache->index->hdr->cache_file_seq + 1;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));

	fd = file_dotlock_open(cache->filepath, NULL, NULL,
			       MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		return -1;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		return -1;
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, NULL, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return -1;
	}

	cache->mmap_refresh = TRUE;
	if (mail_cache_mmap_update(cache, 0,
				   sizeof(struct mail_cache_header)) < 0)
		return -1;

	return 0;
}

int mail_cache_lock(struct mail_cache *cache, int nonblock)
{
	int ret;

	if (cache->locks++ != 0)
		return 1;

	if (nonblock) {
		ret = file_try_lock(cache->fd, F_WRLCK);
		if (ret < 0)
			mail_cache_set_syscall_error(cache, "file_try_lock()");
	} else {
		ret = file_wait_lock(cache->fd, F_WRLCK);
		if (ret <= 0)
			mail_cache_set_syscall_error(cache, "file_wait_lock()");
	}

	if (ret > 0) {
		if (mail_cache_mmap_update(cache, 0, 0) < 0) {
			(void)mail_cache_unlock(cache);
			return -1;
		}

		if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq) {
			mail_cache_unlock(cache);
			return 0;
		}
	}
	return ret;
}

int mail_cache_unlock(struct mail_cache *cache)
{
	if (--cache->locks > 0)
		return 0;

	if (file_wait_lock(cache->fd, F_UNLCK) <= 0) {
		mail_cache_set_syscall_error(cache, "file_wait_lock(F_UNLCK)");
		return -1;
	}

	return 0;
}

int mail_cache_is_locked(struct mail_cache *cache)
{
	return cache->locks > 0;
}

int mail_cache_need_reset(struct mail_cache *cache, uint32_t *new_file_seq_r)
{
	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq) {
		if (mail_cache_lock(cache, TRUE) == 0) {
			*new_file_seq_r = cache->hdr->file_seq;
			return TRUE;
		}
	}

	return FALSE;
}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview)
{
	struct mail_cache_view *view;

	view = i_new(struct mail_cache_view, 1);
	view->cache = cache;
	view->view = iview;
	return view;
}

void mail_cache_view_close(struct mail_cache_view *view)
{
	i_free(view);
}

void mail_cache_mark_missing(struct mail_cache_view *view,
			     enum mail_cache_field fields)
{
	// FIXME
}
