/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "file-cache.h"
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

	/* mark the cache as unusable */
	cache->hdr = NULL;

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

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, -1);

	cache->mmap_base = NULL;
	cache->data = NULL;
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
	struct mail_index_view *view;
	const struct mail_index_ext *ext;

	if (MAIL_CACHE_IS_UNUSABLE(cache) &&
	    (cache->need_compress || MAIL_INDEX_IS_IN_MEMORY(cache->index))) {
		/* reopening does no good */
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

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, cache->fd);

	if (mail_cache_map(cache, 0, 0) < 0)
		return -1;

	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	view = mail_index_view_open(cache->index);
	ext = mail_index_view_get_ext(view, cache->ext_id);
	if (ext == NULL || cache->hdr->file_seq != ext->reset_id) {
		/* still different - maybe a race condition or maybe the
		   file_seq really is corrupted. either way, this shouldn't
		   happen often so we'll just mark cache to be compressed
		   later which fixes this. */
		cache->need_compress = TRUE;
		mail_index_view_close(view);
		return 0;
	}

	mail_index_view_close(view);
	return 1;
}

static int mail_cache_verify_header(struct mail_cache *cache)
{
	const struct mail_cache_header *hdr = cache->data;

	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "File too small");
		return FALSE;
	}

	if (cache->hdr->version != MAIL_CACHE_VERSION) {
		/* version changed - upgrade silently */
		return FALSE;
	}
	if (hdr->compat_sizeof_uoff_t != sizeof(uoff_t) ||
	    hdr->compat_sizeof_time_t != sizeof(time_t)) {
		if (hdr->compat_sizeof_uoff_t == 0 &&
		    hdr->compat_sizeof_time_t == 0) {
			/* FIXME: keep backwards compatibility for a while.
			   set hdr_modified=TRUE so header gets fixed the next
			   time cache is locked. */
			cache->hdr_modified = TRUE;
		} else {
			/* architecture change - handle silently(?) */
			return -1;
		}
	}

	if (cache->hdr->indexid != cache->index->indexid) {
		/* index id changed */
		mail_cache_set_corrupted(cache, "indexid changed");
		return FALSE;
	}

	/* only check the header if we're locked */
	if (!cache->locked)
		return TRUE;

	if (hdr->used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return FALSE;
	}
	if ((hdr->used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return FALSE;
	}

	if (cache->mmap_base != NULL &&
	    hdr->used_file_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "used_file_size too large");
		return FALSE;
	}
	return TRUE;
}

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size)
{
	ssize_t ret;

	if (size == 0)
		size = sizeof(struct mail_cache_header);

	if (cache->file_cache != NULL) {
		cache->data = NULL;
		cache->hdr = NULL;

		ret = file_cache_read(cache->file_cache, offset, size);
		if (ret < 0) {
			// FIXME: ESTALE
			mail_cache_set_syscall_error(cache, "read()");
			return -1;
		}

		cache->data = file_cache_get_map(cache->file_cache,
						 &cache->mmap_length);
		cache->hdr = cache->data;

		if (offset == 0 && !mail_cache_verify_header(cache)) {
			cache->need_compress = TRUE;
			return -1;
		}
		return 0;
	}

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
			/* unusable, waiting for compression or
			   index is in memory */
			i_assert(cache->need_compress ||
				 MAIL_INDEX_IS_IN_MEMORY(cache->index));
			return -1;
		}
	}

	/* map the whole file */
	cache->hdr = NULL;
	cache->mmap_length = 0;

	cache->mmap_base = mmap_ro_file(cache->fd, &cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		cache->mmap_base = NULL;
		cache->data = NULL;
		mail_cache_set_syscall_error(cache, "mmap()");
		return -1;
	}
	cache->data = cache->mmap_base;
	cache->hdr = cache->mmap_base;

	if (!mail_cache_verify_header(cache)) {
		cache->need_compress = TRUE;
		return -1;
	}

	return 0;
}

static int mail_cache_open_and_verify(struct mail_cache *cache)
{
	if (MAIL_INDEX_IS_IN_MEMORY(cache->index))
		return 0;

	cache->fd = open(cache->filepath, O_RDWR);
	if (cache->fd == -1) {
		if (errno == ENOENT) {
			cache->need_compress = TRUE;
			return 0;
		}

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, cache->fd);

	if (mail_cache_map(cache, 0, sizeof(struct mail_cache_header)) < 0)
		return -1;

	return mail_cache_header_fields_read(cache);
}

static struct mail_cache *mail_cache_alloc(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
	cache->filepath =
		i_strconcat(index->filepath, MAIL_CACHE_FILE_SUFFIX, NULL);
	cache->field_pool = pool_alloconly_create("Cache fields", 1024);
	cache->field_name_hash =
		hash_create(default_pool, cache->field_pool, 0,
			    strcase_hash, (hash_cmp_callback_t *)strcasecmp);

	cache->dotlock_settings.timeout = MAIL_CACHE_LOCK_TIMEOUT;
	cache->dotlock_settings.stale_timeout = MAIL_CACHE_LOCK_CHANGE_TIMEOUT;
	cache->dotlock_settings.immediate_stale_timeout =
		MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT;

	if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
		if (index->mmap_disable || index->mmap_no_write)
			cache->file_cache = file_cache_new(-1);
	}

	cache->ext_id =
		mail_index_ext_register(index, "cache", 0,
					sizeof(uint32_t), sizeof(uint32_t));
	mail_index_register_expunge_handler(index, cache->ext_id,
					    mail_cache_expunge_handler);
	mail_index_register_sync_handler(index, cache->ext_id,
					 mail_cache_sync_handler,
                                         MAIL_INDEX_SYNC_HANDLER_INDEX |
					 (cache->file_cache == NULL ? 0 :
					  MAIL_INDEX_SYNC_HANDLER_VIEW));

	if (cache->file_cache != NULL) {
		mail_index_register_sync_lost_handler(index,
			mail_cache_sync_lost_handler);
	}
	return cache;
}

struct mail_cache *mail_cache_open_or_create(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = mail_cache_alloc(index);
	if (mail_cache_open_and_verify(cache) < 0) {
		/* failed for some reason - doesn't really matter,
		   it's disabled for now. */
		mail_cache_file_close(cache);
	}
	return cache;
}

struct mail_cache *mail_cache_create(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = mail_cache_alloc(index);
	cache->need_compress = TRUE;
	return cache;
}

void mail_cache_free(struct mail_cache *cache)
{
	if (cache->file_cache != NULL) {
		mail_index_unregister_sync_lost_handler(cache->index,
			mail_cache_sync_lost_handler);

		file_cache_free(cache->file_cache);
		cache->file_cache = NULL;
	}

	mail_index_unregister_expunge_handler(cache->index, cache->ext_id);
	mail_index_unregister_sync_handler(cache->index, cache->ext_id);

	mail_cache_file_close(cache);

	hash_destroy(cache->field_name_hash);
	pool_unref(cache->field_pool);
	i_free(cache->field_file_map);
	i_free(cache->file_field_map);
	i_free(cache->fields);
	i_free(cache->filepath);
	i_free(cache);
}

static int mail_cache_lock_file(struct mail_cache *cache, int lock_type)
{
	if (cache->index->lock_method != MAIL_INDEX_LOCK_DOTLOCK) {
		return mail_index_lock_fd(cache->index, cache->filepath,
					  cache->fd, lock_type,
					  MAIL_INDEX_LOCK_SECS);
	}

	if (lock_type != F_UNLCK) {
		return file_dotlock_create(&cache->dotlock_settings,
					   cache->filepath, 0, &cache->dotlock);
	} else
		return file_dotlock_delete(&cache->dotlock);
}

int mail_cache_lock(struct mail_cache *cache)
{
	struct mail_index_view *view;
	const struct mail_index_ext *ext;
	int i, ret;

	i_assert(!cache->locked);

	if (MAIL_CACHE_IS_UNUSABLE(cache))
		return 0;

	view = mail_index_view_open(cache->index);
	ext = mail_index_view_get_ext(view, cache->ext_id);
	if (ext == NULL) {
		/* cache not used */
		mail_index_view_close(view);
		return 0;
	}

	if (cache->hdr->file_seq != ext->reset_id) {
		/* we want the latest cache file */
		if ((ret = mail_cache_reopen(cache)) <= 0) {
			mail_index_view_close(view);
			return ret;
		}
	}

	for (i = 0; i < 3; i++) {
		ret = mail_cache_lock_file(cache, F_WRLCK);
		if (ret <= 0)
			break;
		cache->locked = TRUE;

		if (cache->hdr->file_seq == ext->reset_id) {
			/* got it */
			break;
		}

		/* okay, so it was just compressed. try again. */
		(void)mail_cache_unlock(cache);
		if ((ret = mail_cache_reopen(cache)) <= 0)
			break;
		ret = 0;
	}

	if (ret > 0) {
		/* make sure our header is up to date */
		if (cache->file_cache != NULL) {
			file_cache_invalidate(cache->file_cache, 0,
					      sizeof(struct mail_cache_header));
		}
		if (mail_cache_map(cache, 0, 0) == 0)
			cache->hdr_copy = *cache->hdr;
		else {
			(void)mail_cache_unlock(cache);
			ret = -1;
		}
	}

	mail_index_view_close(view);
	i_assert((ret <= 0 && !cache->locked) || (ret > 0 && cache->locked));
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

int mail_cache_unlock(struct mail_cache *cache)
{
	int ret = 0;

	i_assert(cache->locked);

	if (cache->field_header_write_pending)
                ret = mail_cache_header_fields_update(cache);

	cache->locked = FALSE;

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		/* we found it to be broken during the lock. just clean up. */
		cache->hdr_modified = FALSE;
		return -1;
	}

	if (cache->hdr_modified) {
		/* FIXME: for backwards compatibility - keep them for a while */
		cache->hdr_copy.compat_sizeof_uoff_t = sizeof(uoff_t);
		cache->hdr_copy.compat_sizeof_time_t = sizeof(time_t);

		cache->hdr_modified = FALSE;
		if (mail_cache_write(cache, &cache->hdr_copy,
				     sizeof(cache->hdr_copy), 0) < 0)
			ret = -1;
		mail_cache_update_need_compress(cache);
	}

	(void)mail_cache_lock_file(cache, F_UNLCK);
	return ret;
}

int mail_cache_write(struct mail_cache *cache, const void *data, size_t size,
		     uoff_t offset)
{
	if (pwrite_full(cache->fd, data, size, offset) < 0) {
		mail_cache_set_syscall_error(cache, "pwrite_full()");
		return -1;
	}

	if (cache->file_cache != NULL) {
		file_cache_write(cache->file_cache, data, size, offset);

		/* data/hdr pointers may change if file cache was grown */
		cache->data = file_cache_get_map(cache->file_cache,
						 &cache->mmap_length);
		cache->hdr = cache->data;
	}
	return 0;
}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview)
{
	struct mail_cache_view *view;

	view = i_new(struct mail_cache_view, 1);
	view->cache = cache;
	view->view = iview;
	ARRAY_CREATE(&view->tmp_offsets, default_pool, uint32_t, 32);
	view->cached_exists_buf =
		buffer_create_dynamic(default_pool,
				      cache->file_fields_count + 10);
	return view;
}

void mail_cache_view_close(struct mail_cache_view *view)
{
	if (view->cache->field_header_write_pending)
                (void)mail_cache_header_fields_update(view->cache);

	if (view->trans_view != NULL)
		mail_index_view_close(view->trans_view);

	array_free(&view->tmp_offsets);
	buffer_free(view->cached_exists_buf);
	i_free(view);
}
