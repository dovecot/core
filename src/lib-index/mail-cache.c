/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-cache-private.h"

#include <unistd.h>

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

	(void)unlink(cache->filepath);
	mail_cache_file_close(cache);

	va_start(va, fmt);
	t_push();
	mail_index_set_error(cache->index, "Corrupted index cache file %s: %s",
			     cache->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);
}

void mail_cache_file_close(struct mail_cache *cache)
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

int mail_cache_reopen(struct mail_cache *cache)
{
	if (MAIL_CACHE_IS_UNUSABLE(cache) && cache->need_compress) {
		/* unusable, we're just waiting for compression */
		return 0;
	}

	mail_cache_file_close(cache);

	cache->fd = open(cache->filepath, O_RDWR);
	if (cache->fd == -1) {
		if (errno == ENOENT)
			cache->need_compress = TRUE;
		else
			mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	if (mail_cache_map(cache, 0, 0) < 0)
		return -1;

	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq) {
		/* still different - maybe a race condition or maybe the
		   file_seq really is corrupted. either way, this shouldn't
		   happen often so we'll just mark cache to be compressed
		   later which fixes this. */
		cache->need_compress = TRUE;
		return 0;
	}

	return 1;
}

static int mmap_verify_header(struct mail_cache *cache)
{
	const struct mail_cache_header *hdr;

	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "File too small");
		return FALSE;
	}
	cache->hdr = hdr = cache->mmap_base;

	if (cache->hdr->version != MAIL_CACHE_VERSION) {
		/* version changed - upgrade silently */
		return FALSE;
	}

	if (cache->hdr->indexid != cache->index->indexid) {
		/* index id changed */
		mail_cache_set_corrupted(cache, "indexid changed");
		return FALSE;
	}

	/* only check the header if we're locked */
	if (cache->locked)
		return TRUE;

	if (hdr->used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return FALSE;
	}
	if ((hdr->used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return FALSE;
	}

	if (hdr->used_file_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "used_file_size too large");
		return FALSE;
	}
	return TRUE;
}

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size)
{
	if (size == 0)
		size = sizeof(struct mail_cache_header);

	if (offset < cache->mmap_length &&
	    size <= cache->mmap_length - offset) {
		/* already mapped */
		return 0;
	}

	if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	} else {
		if (cache->fd == -1) {
			/* unusable, waiting for compression */
			i_assert(cache->need_compress);
			return -1;
		}
	}

	/* map the whole file */
	cache->hdr = NULL;
	cache->mmap_length = 0;

	cache->mmap_base = mmap_ro_file(cache->fd, &cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		cache->mmap_base = NULL;
		mail_cache_set_syscall_error(cache, "mmap()");
		return -1;
	}

	if (!mmap_verify_header(cache)) {
		cache->need_compress = TRUE;
		return -1;
	}

	return 0;
}

static int mail_cache_open_and_verify(struct mail_cache *cache)
{
	cache->filepath = i_strconcat(cache->index->filepath,
				      MAIL_CACHE_FILE_PREFIX, NULL);

	cache->fd = open(cache->filepath, O_RDWR);
	if (cache->fd == -1) {
		if (errno == ENOENT) {
			cache->need_compress = TRUE;
			return 0;
		}

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	if (mail_cache_map(cache, 0, sizeof(struct mail_cache_header)) < 0)
		return -1;

	return mail_cache_header_fields_read(cache);
}

struct mail_cache *mail_cache_open_or_create(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
        cache->field_pool = pool_alloconly_create("Cache fields", 1024);
	cache->field_name_hash =
		hash_create(default_pool, cache->field_pool, 0,
			    strcase_hash, (hash_cmp_callback_t *)strcasecmp);

	if (!index->mmap_disable && !index->mmap_no_write) {
		if (mail_cache_open_and_verify(cache) < 0) {
			/* failed for some reason - doesn't really matter,
			   it's disabled for now. */
			mail_cache_file_close(cache);
		}
	}

	return cache;
}

void mail_cache_free(struct mail_cache *cache)
{
	mail_cache_file_close(cache);

	hash_destroy(cache->field_name_hash);
	pool_unref(cache->field_pool);
	i_free(cache->field_file_map);
	i_free(cache->file_field_map);
	i_free(cache->fields);
	i_free(cache->filepath);
	i_free(cache);
}

int mail_cache_lock(struct mail_cache *cache)
{
	unsigned int lock_id;
	int i, ret;

	i_assert(!cache->locked);

	if (MAIL_CACHE_IS_UNUSABLE(cache))
		return 0;

	if (mail_index_lock_shared(cache->index, TRUE, &lock_id) < 0)
		return -1;

	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq) {
		/* we want the latest cache file */
		if ((ret = mail_cache_reopen(cache)) <= 0) {
			mail_index_unlock(cache->index, lock_id);
			return ret;
		}
	}

	for (i = 0; i < 3; i++) {
		ret = mail_index_lock_fd(cache->index, cache->fd, F_WRLCK,
					 MAIL_INDEX_LOCK_SECS);
		if (ret <= 0) {
			mail_cache_set_syscall_error(cache,
				"mail_index_wait_lock_fd()");
			break;
		}
		cache->locked = TRUE;

		if (cache->hdr->file_seq == cache->index->hdr->cache_file_seq) {
			/* got it */
			break;
		}

		/* okay, so it was just compressed. try again. */
		mail_cache_unlock(cache);
		if ((ret = mail_cache_reopen(cache)) <= 0)
			break;
		ret = 0;
	}

	if (ret > 0)
		cache->hdr_copy = *cache->hdr;

	mail_index_unlock(cache->index, lock_id);
	return ret;
}

static void mail_cache_update_need_compress(struct mail_cache *cache)
{
	const struct mail_cache_header *hdr = cache->hdr;
	unsigned int cont_percentage;
	uoff_t max_del_space;

        cont_percentage = hdr->continued_record_count * 100 /
		(cache->index->map->records_count == 0 ? 1 :
		 cache->index->map->records_count);
	if (cont_percentage >= COMPRESS_CONTINUED_PERCENTAGE &&
	    hdr->used_file_size >= COMPRESS_MIN_SIZE) {
		/* too many continued rows, compress */
		cache->need_compress = TRUE;
	}

	/* see if we've reached the max. deleted space in file */
	max_del_space = hdr->used_file_size / 100 * COMPRESS_PERCENTAGE;
	if (hdr->deleted_space >= max_del_space &&
	    hdr->used_file_size >= COMPRESS_MIN_SIZE)
		cache->need_compress = TRUE;
}

void mail_cache_unlock(struct mail_cache *cache)
{
	i_assert(cache->locked);

	if (cache->field_header_write_pending)
                (void)mail_cache_header_fields_update(cache);

	cache->locked = FALSE;

	if (cache->hdr_modified) {
		cache->hdr_modified = FALSE;
		if (pwrite_full(cache->fd, &cache->hdr_copy,
				sizeof(cache->hdr_copy), 0) < 0)
			mail_cache_set_syscall_error(cache, "pwrite_full()");
                mail_cache_update_need_compress(cache);
	}

	if (mail_index_lock_fd(cache->index, cache->fd, F_UNLCK, 0) <= 0) {
		mail_cache_set_syscall_error(cache,
			"mail_index_wait_lock_fd(F_UNLCK)");
	}
}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview)
{
	struct mail_cache_view *view;

	view = i_new(struct mail_cache_view, 1);
	view->cache = cache;
	view->view = iview;
	view->offsets_buf = buffer_create_dynamic(default_pool, 128);
	view->cached_exists_buf =
		buffer_create_dynamic(default_pool,
				      cache->file_fields_count + 10);
	return view;
}

void mail_cache_view_close(struct mail_cache_view *view)
{
	if (view->cache->field_header_write_pending)
                (void)mail_cache_header_fields_update(view->cache);

	buffer_free(view->offsets_buf);
	buffer_free(view->cached_exists_buf);
	i_free(view);
}
