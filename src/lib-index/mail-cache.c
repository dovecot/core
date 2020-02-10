/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "nfs-workarounds.h"
#include "file-cache.h"
#include "mmap-util.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-cache-private.h"
#include "ioloop.h"

#include <unistd.h>

#define MAIL_CACHE_MIN_HEADER_READ_SIZE 4096

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function)
{
	mail_index_file_set_syscall_error(cache->index, cache->filepath,
					  function);
}

static void mail_cache_unlink(struct mail_cache *cache)
{
	if (!cache->index->readonly && !MAIL_INDEX_IS_IN_MEMORY(cache->index))
		i_unlink_if_exists(cache->filepath);
}

void mail_cache_reset(struct mail_cache *cache)
{
	mail_cache_unlink(cache);
	/* mark the cache as unusable */
	cache->hdr = NULL;
}

void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
{
	va_list va;

	mail_cache_reset(cache);

	va_start(va, fmt);
	T_BEGIN {
		mail_index_set_error(cache->index,
				     "Corrupted index cache file %s: %s",
				     cache->filepath,
				     t_strdup_vprintf(fmt, va));
	} T_END;
	va_end(va);
}

void mail_cache_set_seq_corrupted_reason(struct mail_cache_view *cache_view,
					 uint32_t seq, const char *reason)
{
	uint32_t empty = 0;
	struct mail_cache *cache = cache_view->cache;
	struct mail_index_view *view = cache_view->view;

	mail_index_set_error(cache->index,
			     "Corrupted record in index cache file %s: %s",
					     cache->filepath, reason);

	/* drop cache pointer */
	struct mail_index_transaction *t =
		mail_index_transaction_begin(view, MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_ext(t, seq, cache->ext_id, &empty, NULL);

	if (mail_index_transaction_commit(&t) < 0)
		mail_cache_reset(cache);
	else
		mail_cache_expunge_count(cache, 1);
}

void mail_cache_file_close(struct mail_cache *cache)
{
	if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, -1);
	if (cache->read_buf != NULL)
		buffer_set_used_size(cache->read_buf, 0);

	cache->mmap_base = NULL;
	cache->hdr = NULL;
	cache->mmap_length = 0;
	cache->last_field_header_offset = 0;

	if (cache->file_lock != NULL)
		file_lock_free(&cache->file_lock);
	cache->locked = FALSE;

	if (cache->fd != -1) {
		if (close(cache->fd) < 0)
			mail_cache_set_syscall_error(cache, "close()");
		cache->fd = -1;
	}
	cache->opened = FALSE;
}

static void mail_cache_init_file_cache(struct mail_cache *cache)
{
	struct stat st;

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, cache->fd);

	if (fstat(cache->fd, &st) == 0) {
		if (cache->file_cache != NULL)
			(void)file_cache_set_size(cache->file_cache, st.st_size);
	} else if (!ESTALE_FSTAT(errno)) {
		mail_cache_set_syscall_error(cache, "fstat()");
	}

	cache->last_stat_size = st.st_size;
	cache->st_ino = st.st_ino;
	cache->st_dev = st.st_dev;
}

static int mail_cache_try_open(struct mail_cache *cache)
{
	const void *data;

	i_assert(!cache->opened);
	cache->opened = TRUE;

	if (MAIL_INDEX_IS_IN_MEMORY(cache->index))
		return 0;

	i_assert(cache->fd == -1);
	cache->fd = nfs_safe_open(cache->filepath,
				  cache->index->readonly ? O_RDONLY : O_RDWR);
	if (cache->fd == -1) {
		mail_cache_file_close(cache);
		if (errno == ENOENT) {
			cache->need_compress_file_seq = 0;
			return 0;
		}

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	mail_cache_init_file_cache(cache);

	if (mail_cache_map(cache, 0, 0, &data) < 0) {
		mail_cache_file_close(cache);
		return -1;
	}
	return 1;
}

static bool mail_cache_need_reopen(struct mail_cache *cache)
{
	struct stat st;

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		if (cache->need_compress_file_seq != 0) {
			/* we're waiting for compression */
			return FALSE;
		}
		if (MAIL_INDEX_IS_IN_MEMORY(cache->index)) {
			/* disabled */
			return FALSE;
		}
	}

	if (cache->fd == -1)
		return TRUE;

	/* see if the file has changed */
	if ((cache->index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0) {
		i_assert(!cache->locked);
		nfs_flush_file_handle_cache(cache->filepath);
	}
	if (nfs_safe_stat(cache->filepath, &st) < 0) {
		mail_cache_set_syscall_error(cache, "stat()");
		return TRUE;
	}

	if (st.st_ino != cache->st_ino ||
	    !CMP_DEV_T(st.st_dev, cache->st_dev)) {
		/* file changed */
		return TRUE;
	}

	if ((cache->index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0) {
		/* if the old file has been deleted, the new file may have
		   the same inode as the old one. we'll catch this here by
		   checking if fstat() fails with ESTALE */
		if (fstat(cache->fd, &st) < 0) {
			if (ESTALE_FSTAT(errno))
				return TRUE;
			mail_cache_set_syscall_error(cache, "fstat()");
			return FALSE;
		}
	}
	return FALSE;
}

static int mail_cache_reopen_now(struct mail_cache *cache)
{
	struct mail_index_view *view;
	const struct mail_index_ext *ext;

	mail_cache_file_close(cache);

	if (mail_cache_try_open(cache) <= 0)
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
		cache->need_compress_file_seq = cache->hdr->file_seq;
		mail_index_view_close(&view);
		return 0;
	}

	mail_index_view_close(&view);
	i_assert(!MAIL_CACHE_IS_UNUSABLE(cache));
	return 1;
}

int mail_cache_reopen(struct mail_cache *cache)
{
	i_assert(!cache->locked);

	if (!mail_cache_need_reopen(cache)) {
		/* reopening does no good */
		return 0;
	}
	return mail_cache_reopen_now(cache);
}

static void mail_cache_update_need_compress(struct mail_cache *cache)
{
	const struct mail_index_cache_optimization_settings *set =
		&cache->index->optimization_set.cache;
	const struct mail_cache_header *hdr = cache->hdr;
	struct stat st;
	unsigned int msg_count;
	unsigned int records_count, cont_percentage, delete_percentage;
	bool want_compress = FALSE;

	if (hdr->minor_version == 0) {
		/* compress to get ourself into the new header version */
		cache->need_compress_file_seq = hdr->file_seq;
		return;
	}

	msg_count = cache->index->map->rec_map->records_count;
	if (msg_count == 0)
		records_count = 1;
	else if (hdr->record_count == 0 || hdr->record_count > msg_count*2) {
		/* probably not the real record_count, but hole offset that
		   Dovecot <=v2.1 versions used to use in this position.
		   we already checked that minor_version>0, but this could
		   happen if old Dovecot was used to access mailbox after
		   it had been updated. */
		records_count = I_MAX(msg_count, 1);
		cache->hdr_copy.record_count = msg_count;
		cache->hdr_modified = TRUE;
	} else {
		records_count = hdr->record_count;
	}

	cont_percentage = hdr->continued_record_count * 100 / records_count;
	if (cont_percentage >= set->compress_continued_percentage) {
		/* too many continued rows, compress */
		want_compress = TRUE;
	}

	delete_percentage = hdr->deleted_record_count * 100 /
		(records_count + hdr->deleted_record_count);
	if (delete_percentage >= set->compress_delete_percentage) {
		/* too many deleted records, compress */
		want_compress = TRUE;
	}

	if (want_compress) {
		if (fstat(cache->fd, &st) < 0) {
			if (!ESTALE_FSTAT(errno))
				mail_cache_set_syscall_error(cache, "fstat()");
			return;
		}
		if ((uoff_t)st.st_size >= set->compress_min_size)
			cache->need_compress_file_seq = hdr->file_seq;
	}

}

static bool mail_cache_verify_header(struct mail_cache *cache,
				     const struct mail_cache_header *hdr)
{
	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "File too small");
		return FALSE;
	}

	if (hdr->major_version != MAIL_CACHE_MAJOR_VERSION) {
		/* version changed - upgrade silently */
		mail_cache_unlink(cache);
		return FALSE;
	}
	if (hdr->compat_sizeof_uoff_t != sizeof(uoff_t)) {
		/* architecture change - handle silently(?) */
		mail_cache_unlink(cache);
		return FALSE;
	}

	if (hdr->indexid != cache->index->indexid) {
		/* index id changed - handle silently */
		mail_cache_unlink(cache);
		return FALSE;
	}
	if (hdr->file_seq == 0) {
		mail_cache_set_corrupted(cache, "file_seq is 0");
		return FALSE;
	}
	return TRUE;
}

static int
mail_cache_map_finish(struct mail_cache *cache, uoff_t offset, size_t size,
		      const void *hdr_data, bool copy_hdr)
{
	const struct mail_cache_header *hdr = hdr_data;

	if (offset == 0) {
		/* verify the header validity only with offset=0. this way
		   we won't waste time re-verifying it all the time */
		if (!mail_cache_verify_header(cache, hdr)) {
			cache->need_compress_file_seq =
				!MAIL_CACHE_IS_UNUSABLE(cache) &&
				cache->hdr->file_seq != 0 ?
				cache->hdr->file_seq : 0;
			cache->hdr = NULL;
			return -1;
		}
	}
	if (hdr_data != NULL) {
		if (!copy_hdr)
			cache->hdr = hdr;
		else {
			memcpy(&cache->hdr_ro_copy, hdr,
			       sizeof(cache->hdr_ro_copy));
			cache->hdr = &cache->hdr_ro_copy;
		}
		mail_cache_update_need_compress(cache);
	} else {
		i_assert(cache->hdr != NULL);
	}
	i_assert(cache->hdr->file_seq != 0);

	if (offset + size > cache->mmap_length)
		return 0;
	return 1;
}

static int
mail_cache_map_with_read(struct mail_cache *cache, size_t offset, size_t size,
			 const void **data_r)
{
	const void *hdr_data;
	void *data;
	ssize_t ret;

	if (cache->read_buf == NULL) {
		cache->read_buf =
			buffer_create_dynamic(default_pool, size);
	} else if (cache->read_offset <= offset &&
		   cache->read_offset + cache->read_buf->used >= offset+size) {
		/* already mapped */
		*data_r = CONST_PTR_OFFSET(cache->read_buf->data,
					   offset - cache->read_offset);
		hdr_data = offset == 0 ? *data_r : NULL;
		return mail_cache_map_finish(cache, offset, size, hdr_data, TRUE);
	} else {
		buffer_set_used_size(cache->read_buf, 0);
	}
	if (offset == 0 && size < MAIL_CACHE_MIN_HEADER_READ_SIZE) {
		/* we can usually read the fields header after the cache
		   header. we need them both, so try to read them all with one
		   pread() call. */
		size = MAIL_CACHE_MIN_HEADER_READ_SIZE;
	}

	data = buffer_append_space_unsafe(cache->read_buf, size);
	ret = pread(cache->fd, data, size, offset);
	if (ret < 0) {
		if (errno != ESTALE)
			mail_cache_set_syscall_error(cache, "read()");

		buffer_set_used_size(cache->read_buf, 0);
		cache->hdr = NULL;
		cache->mmap_length = 0;
		return -1;
	}
	buffer_set_used_size(cache->read_buf, ret);

	cache->read_offset = offset;
	cache->mmap_length = offset + cache->read_buf->used;

	*data_r = data;
	hdr_data = offset == 0 ? *data_r : NULL;
	return mail_cache_map_finish(cache, offset,
				     cache->read_buf->used, hdr_data, TRUE);
}

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size,
		   const void **data_r)
{
	struct stat st;
	const void *data;
	ssize_t ret;

	if (size == 0)
		size = sizeof(struct mail_cache_header);

	/* verify offset + size before trying to allocate a huge amount of
	   memory due to them. note that we may be prefetching more than we
	   actually need, so don't fail too early. */
	if ((size > cache->mmap_length || offset + size > cache->mmap_length) &&
	    (offset > 0 || size > sizeof(struct mail_cache_header))) {
		if (fstat(cache->fd, &st) < 0) {
			i_error("fstat(%s) failed: %m", cache->filepath);
			return -1;
		}
		cache->last_stat_size = st.st_size;
		if (offset >= (uoff_t)st.st_size) {
			*data_r = NULL;
			return 0;
		}
		if (offset + size > (uoff_t)st.st_size)
			size = st.st_size - offset;
	}

	cache->remap_counter++;
	if (cache->map_with_read)
		return mail_cache_map_with_read(cache, offset, size, data_r);

	if (cache->file_cache != NULL) {
		ret = file_cache_read(cache->file_cache, offset, size);
		if (ret < 0) {
                        /* In case of ESTALE we'll simply fail without error
                           messages. The caller will then just have to
                           fallback to generating the value itself.

                           We can't simply reopen the cache flie, because
                           using it requires also having updated file
                           offsets. */
                        if (errno != ESTALE)
                                mail_cache_set_syscall_error(cache, "read()");
			cache->hdr = NULL;
			return -1;
		}

		data = file_cache_get_map(cache->file_cache,
					  &cache->mmap_length);
		*data_r = offset > cache->mmap_length ? NULL :
			CONST_PTR_OFFSET(data, offset);
		return mail_cache_map_finish(cache, offset, size,
					     offset == 0 ? data : NULL, TRUE);
	}

	if (offset < cache->mmap_length &&
	    size <= cache->mmap_length - offset) {
		/* already mapped */
		i_assert(cache->mmap_base != NULL);
		*data_r = CONST_PTR_OFFSET(cache->mmap_base, offset);
		return 1;
	}

	if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	} else {
		if (cache->fd == -1) {
			/* unusable, waiting for compression or
			   index is in memory */
			i_assert(cache->need_compress_file_seq != 0 ||
				 MAIL_INDEX_IS_IN_MEMORY(cache->index));
			return -1;
		}
	}

	/* map the whole file */
	cache->hdr = NULL;
	cache->mmap_length = 0;
	if (cache->read_buf != NULL)
		buffer_set_used_size(cache->read_buf, 0);

	cache->mmap_base = mmap_ro_file(cache->fd, &cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		cache->mmap_base = NULL;
		if (ioloop_time != cache->last_mmap_error_time) {
			cache->last_mmap_error_time = ioloop_time;
			mail_cache_set_syscall_error(cache, t_strdup_printf(
				"mmap(size=%"PRIuSIZE_T")", cache->mmap_length));
		}
		cache->mmap_length = 0;
		return -1;
	}
	*data_r = offset > cache->mmap_length ? NULL :
		CONST_PTR_OFFSET(cache->mmap_base, offset);
	return mail_cache_map_finish(cache, offset, size,
				     cache->mmap_base, FALSE);
}

int mail_cache_open_and_verify(struct mail_cache *cache)
{
	int ret;

	if (cache->opened)
		return 0;
	ret = mail_cache_try_open(cache);
	if (ret > 0)
		ret = mail_cache_header_fields_read(cache);
	if (ret < 0) {
		/* failed for some reason - doesn't really matter,
		   it's disabled for now. */
		mail_cache_file_close(cache);
	}
	return ret;
}

static struct mail_cache *mail_cache_alloc(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
	cache->filepath =
		i_strconcat(index->filepath, MAIL_CACHE_FILE_SUFFIX, NULL);
	cache->field_pool = pool_alloconly_create("Cache fields", 2048);
	hash_table_create(&cache->field_name_hash, cache->field_pool, 0,
			  strcase_hash, strcasecmp);

	cache->dotlock_settings.use_excl_lock =
		(index->flags & MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL) != 0;
	cache->dotlock_settings.nfs_flush =
		(index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0;
	cache->dotlock_settings.timeout =
		I_MIN(MAIL_CACHE_LOCK_TIMEOUT, index->max_lock_timeout_secs);
	cache->dotlock_settings.stale_timeout = MAIL_CACHE_LOCK_CHANGE_TIMEOUT;

	if (!MAIL_INDEX_IS_IN_MEMORY(index) &&
	    (index->flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) != 0)
		cache->file_cache = file_cache_new_path(-1, cache->filepath);
	cache->map_with_read =
		(cache->index->flags & MAIL_INDEX_OPEN_FLAG_SAVEONLY) != 0;

	cache->ext_id =
		mail_index_ext_register(index, "cache", 0,
					sizeof(uint32_t), sizeof(uint32_t));
	mail_index_register_expunge_handler(index, cache->ext_id, FALSE,
					    mail_cache_expunge_handler, cache);
	return cache;
}

struct mail_cache *mail_cache_open_or_create(struct mail_index *index)
{
	struct mail_cache *cache;

	cache = mail_cache_alloc(index);
	return cache;
}

void mail_cache_free(struct mail_cache **_cache)
{
	struct mail_cache *cache = *_cache;

	*_cache = NULL;
	if (cache->file_cache != NULL)
		file_cache_free(&cache->file_cache);

	mail_index_unregister_expunge_handler(cache->index, cache->ext_id);
	mail_cache_file_close(cache);

	if (cache->read_buf != NULL)
		buffer_free(&cache->read_buf);
	hash_table_destroy(&cache->field_name_hash);
	pool_unref(&cache->field_pool);
	i_free(cache->field_file_map);
	i_free(cache->file_field_map);
	i_free(cache->fields);
	i_free(cache->filepath);
	i_free(cache);
}

static int mail_cache_lock_file(struct mail_cache *cache, bool nonblock)
{
	unsigned int timeout_secs;
	int ret;

	if (cache->last_lock_failed) {
		/* previous locking failed. don't waste time waiting on it
		   again, just try once to see if it's available now. */
		nonblock = TRUE;
	}

	i_assert(cache->file_lock == NULL);
	if (cache->index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
		timeout_secs = I_MIN(MAIL_CACHE_LOCK_TIMEOUT,
				     cache->index->max_lock_timeout_secs);

		ret = mail_index_lock_fd(cache->index, cache->filepath,
					 cache->fd, F_WRLCK,
					 nonblock ? 0 : timeout_secs,
					 &cache->file_lock);
	} else {
		struct dotlock *dotlock;
		enum dotlock_create_flags flags =
			nonblock ? DOTLOCK_CREATE_FLAG_NONBLOCK : 0;

		ret = file_dotlock_create(&cache->dotlock_settings,
					  cache->filepath, flags, &dotlock);
		if (ret > 0)
			cache->file_lock = file_lock_from_dotlock(&dotlock);
		else if (ret < 0) {
			mail_cache_set_syscall_error(cache,
						     "file_dotlock_create()");
		}
	}
	cache->last_lock_failed = ret <= 0;

	/* don't bother warning if locking failed due to a timeout. since cache
	   updating isn't all that important we're using a very short timeout
	   so it can be triggered sometimes on heavy load */
	if (ret <= 0)
		return ret;

	mail_index_flush_read_cache(cache->index, cache->filepath, cache->fd,
				    TRUE);
	return 1;
}

static void mail_cache_unlock_file(struct mail_cache *cache)
{
	file_unlock(&cache->file_lock);
}

static int
mail_cache_lock_full(struct mail_cache *cache, bool nonblock)
{
	const struct mail_index_ext *ext;
	const void *data;
	struct mail_index_view *iview;
	uint32_t reset_id;
	int i;

	i_assert(!cache->locked);

	if (!cache->opened)
		(void)mail_cache_open_and_verify(cache);

	if (MAIL_CACHE_IS_UNUSABLE(cache) ||
	    MAIL_INDEX_IS_IN_MEMORY(cache->index) ||
	    cache->index->readonly)
		return 0;

	for (;;) {
		if (mail_cache_lock_file(cache, nonblock) <= 0)
			return -1;
		i_assert(!MAIL_CACHE_IS_UNUSABLE(cache));
		if (!mail_cache_need_reopen(cache)) {
			/* locked the latest file */
			break;
		}
		if (mail_cache_reopen_now(cache) <= 0) {
			i_assert(cache->file_lock == NULL);
			return -1;
		}
		i_assert(cache->file_lock == NULL);
		/* okay, so it was just compressed. try again. */
	}

	/* now verify that the index reset_id matches the cache's file_seq */
	for (i = 0; ; i++) {
		iview = mail_index_view_open(cache->index);
		ext = mail_index_view_get_ext(iview, cache->ext_id);
		reset_id = ext == NULL ? 0 : ext->reset_id;
		mail_index_view_close(&iview);

		if (cache->hdr->file_seq == reset_id)
			break;
		/* mismatch. try refreshing index once. if that doesn't help,
		   we can't use the cache. */
		if (i > 0 || cache->index->mapping) {
			mail_cache_unlock_file(cache);
			return 0;
		}
		if (mail_index_refresh(cache->index) < 0) {
			mail_cache_unlock_file(cache);
			return -1;
		}
	}

	/* successfully locked - make sure our header is up to date */
	cache->locked = TRUE;
	cache->hdr_modified = FALSE;

	if (cache->file_cache != NULL) {
		file_cache_invalidate(cache->file_cache, 0,
				      sizeof(struct mail_cache_header));
	}
	if (cache->read_buf != NULL)
		buffer_set_used_size(cache->read_buf, 0);
	if (mail_cache_map(cache, 0, 0, &data) <= 0) {
		(void)mail_cache_unlock(cache);
		return -1;
	}
	cache->hdr_copy = *cache->hdr;
	return 1;
}

int mail_cache_lock(struct mail_cache *cache)
{
	return mail_cache_lock_full(cache, FALSE);
}

int mail_cache_try_lock(struct mail_cache *cache)
{
	return mail_cache_lock_full(cache, TRUE);
}

int mail_cache_unlock(struct mail_cache *cache)
{
	int ret = 0;

	i_assert(cache->locked);

	if (cache->field_header_write_pending)
                ret = mail_cache_header_fields_update(cache);

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		/* we found it to be broken during the lock. just clean up. */
		cache->hdr_modified = FALSE;
		cache->locked = FALSE;
		return -1;
	}

	if (cache->hdr_modified) {
		cache->hdr_modified = FALSE;
		if (mail_cache_write(cache, &cache->hdr_copy,
				     sizeof(cache->hdr_copy), 0) < 0)
			ret = -1;
		cache->hdr_ro_copy = cache->hdr_copy;
		mail_cache_update_need_compress(cache);
	}

	if (cache->index->fsync_mode == FSYNC_MODE_ALWAYS) {
		if (fdatasync(cache->fd) < 0)
			mail_cache_set_syscall_error(cache, "fdatasync()");
	}

	cache->locked = FALSE;
	mail_cache_unlock_file(cache);
	return ret;
}

int mail_cache_write(struct mail_cache *cache, const void *data, size_t size,
		     uoff_t offset)
{
	i_assert(cache->locked);

	if (pwrite_full(cache->fd, data, size, offset) < 0) {
		mail_cache_set_syscall_error(cache, "pwrite_full()");
		return -1;
	}

	if (cache->file_cache != NULL)
		file_cache_write(cache->file_cache, data, size, offset);
	if (cache->read_buf != NULL)
		buffer_set_used_size(cache->read_buf, 0);
	return 0;
}

int mail_cache_append(struct mail_cache *cache, const void *data, size_t size,
		      uint32_t *offset)
{
	struct stat st;

	if (*offset == 0) {
		if (fstat(cache->fd, &st) < 0) {
			if (!ESTALE_FSTAT(errno))
				mail_cache_set_syscall_error(cache, "fstat()");
			return -1;
		}
		cache->last_stat_size = st.st_size;
		if ((uoff_t)st.st_size > cache->index->optimization_set.cache.max_size) {
			mail_cache_set_corrupted(cache, "Cache file too large");
			return -1;
		}
		*offset = st.st_size;
	}
	if (*offset >= cache->index->optimization_set.cache.max_size ||
	    cache->index->optimization_set.cache.max_size - *offset < size) {
		mail_cache_set_corrupted(cache, "Cache file too large");
		return -1;
	}
	if (mail_cache_write(cache, data, size, *offset) < 0)
		return -1;

	/* FIXME: this is updated only so that older Dovecot versions (<=v2.1)
	   can read this file. we can remove this later. */
	cache->hdr_modified = TRUE;
	cache->hdr_copy.backwards_compat_used_file_size = *offset + size;
	return 0;
}

bool mail_cache_exists(struct mail_cache *cache)
{
	return !MAIL_CACHE_IS_UNUSABLE(cache);
}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview)
{
	struct mail_cache_view *view;

	view = i_new(struct mail_cache_view, 1);
	view->cache = cache;
	view->view = iview;
	view->cached_exists_buf =
		buffer_create_dynamic(default_pool,
				      cache->file_fields_count + 10);
	return view;
}

void mail_cache_view_close(struct mail_cache_view **_view)
{
	struct mail_cache_view *view = *_view;

	i_assert(view->trans_view == NULL);

	*_view = NULL;
	if (view->cache->field_header_write_pending &&
	    !view->cache->compressing)
                (void)mail_cache_header_fields_update(view->cache);

	buffer_free(&view->cached_exists_buf);
	i_free(view);
}

void mail_cache_view_update_cache_decisions(struct mail_cache_view *view,
					    bool update)
{
	view->no_decision_updates = !update;
}

uint32_t mail_cache_get_first_new_seq(struct mail_index_view *view)
{
	const struct mail_index_header *idx_hdr;
	uint32_t first_new_seq, message_count;

	idx_hdr = mail_index_get_header(view);
	if (idx_hdr->day_first_uid[7] == 0)
		return 1;

	if (!mail_index_lookup_seq_range(view, idx_hdr->day_first_uid[7],
					 (uint32_t)-1, &first_new_seq,
					 &message_count)) {
		/* all messages are too old */
		return message_count+1;
	}
	return first_new_seq;
}
