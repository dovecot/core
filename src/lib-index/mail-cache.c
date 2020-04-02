/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "hash.h"
#include "llist.h"
#include "nfs-workarounds.h"
#include "file-cache.h"
#include "mmap-util.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-cache-private.h"
#include "ioloop.h"

#include <unistd.h>

#define MAIL_CACHE_MIN_HEADER_READ_SIZE 4096

static struct event_category event_category_mail_cache = {
	.name = "mail-cache",
};

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

	if (mail_index_transaction_commit(&t) < 0) {
		/* I/O error (e.g. out of disk space). Ignore this for now,
		   maybe it works again later. */
		return;
	}
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
	int ret;

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
			cache->need_purge_file_seq = 0;
			return 0;
		}

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	mail_cache_init_file_cache(cache);

	if ((ret = mail_cache_map_all(cache)) <= 0) {
		mail_cache_file_close(cache);
		return ret;
	}
	return 1;
}

static bool mail_cache_need_reopen(struct mail_cache *cache)
{
	struct stat st;

	if (MAIL_INDEX_IS_IN_MEMORY(cache->index)) {
		/* disabled */
		return FALSE;
	}

	if (cache->fd == -1)
		return TRUE;

	/* see if the file has changed */
	if ((cache->index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0) {
		i_assert(!cache->locked);
		nfs_flush_file_handle_cache(cache->filepath);
	}
	if (nfs_safe_stat(cache->filepath, &st) < 0) {
		/* if cache was already marked as corrupted, don't log errors
		   about nonexistent cache file */
		if (cache->hdr != NULL || errno != ENOENT)
			mail_cache_set_syscall_error(cache, "stat()");
		return TRUE;
	}
	cache->last_stat_size = st.st_size;

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

int mail_cache_reopen(struct mail_cache *cache)
{
	mail_cache_file_close(cache);
	return mail_cache_open_and_verify(cache);
}

static void mail_cache_update_need_purge(struct mail_cache *cache)
{
	const struct mail_index_cache_optimization_settings *set =
		&cache->index->optimization_set.cache;
	const struct mail_cache_header *hdr = cache->hdr;
	struct stat st;
	unsigned int msg_count;
	unsigned int records_count, cont_percentage, delete_percentage;
	bool want_purge = FALSE;

	if (hdr->minor_version == 0) {
		/* purge to get ourself into the new header version */
		cache->need_purge_file_seq = hdr->file_seq;
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
	} else {
		records_count = hdr->record_count;
	}

	cont_percentage = hdr->continued_record_count * 100 / records_count;
	if (cont_percentage >= set->purge_continued_percentage) {
		/* too many continued rows, purge */
		want_purge = TRUE;
	}

	delete_percentage = hdr->deleted_record_count * 100 /
		(records_count + hdr->deleted_record_count);
	if (delete_percentage >= set->purge_delete_percentage) {
		/* too many deleted records, purge */
		want_purge = TRUE;
	}

	if (want_purge) {
		if (fstat(cache->fd, &st) < 0) {
			if (!ESTALE_FSTAT(errno))
				mail_cache_set_syscall_error(cache, "fstat()");
			return;
		}
		if ((uoff_t)st.st_size >= set->purge_min_size)
			cache->need_purge_file_seq = hdr->file_seq;
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
		      const void *hdr_data, bool copy_hdr, bool *corrupted_r)
{
	const struct mail_cache_header *hdr = hdr_data;

	*corrupted_r = FALSE;

	if (offset == 0) {
		/* verify the header validity only with offset=0. this way
		   we won't waste time re-verifying it all the time */
		if (!mail_cache_verify_header(cache, hdr)) {
			cache->need_purge_file_seq =
				!MAIL_CACHE_IS_UNUSABLE(cache) &&
				cache->hdr->file_seq != 0 ?
				cache->hdr->file_seq : 0;
			cache->hdr = NULL;
			*corrupted_r = TRUE;
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
		mail_cache_update_need_purge(cache);
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
			 const void **data_r, bool *corrupted_r)
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
		return mail_cache_map_finish(cache, offset, size, hdr_data,
					     TRUE, corrupted_r);
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
				     cache->read_buf->used, hdr_data,
				     TRUE, corrupted_r);
}

static int
mail_cache_map_full(struct mail_cache *cache, size_t offset, size_t size,
		    const void **data_r, bool *corrupted_r)
{
	struct stat st;
	const void *data;
	ssize_t ret;

	*corrupted_r = FALSE;

	if (size == 0)
		size = sizeof(struct mail_cache_header);

	/* verify offset + size before trying to allocate a huge amount of
	   memory due to them. note that we may be prefetching more than we
	   actually need, so don't fail too early. */
	if ((size > cache->mmap_length || offset + size > cache->mmap_length) &&
	    (offset > 0 || size > sizeof(struct mail_cache_header))) {
		if (fstat(cache->fd, &st) < 0) {
			e_error(cache->index->event,
				"fstat(%s) failed: %m", cache->filepath);
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
		return mail_cache_map_with_read(cache, offset, size, data_r,
						corrupted_r);

	if (cache->file_cache != NULL) {
		ret = file_cache_read(cache->file_cache, offset, size);
		if (ret < 0) {
                        /* In case of ESTALE we'll simply fail without error
                           messages. The caller will then just have to
                           fallback to generating the value itself.

                           We can't simply reopen the cache file, because
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
					     offset == 0 ? data : NULL, TRUE,
					     corrupted_r);
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
			/* unusable, waiting for purging or
			   index is in memory */
			i_assert(cache->need_purge_file_seq != 0 ||
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
				"mmap(size=%zu)", cache->mmap_length));
		}
		cache->mmap_length = 0;
		return -1;
	}
	*data_r = offset > cache->mmap_length ? NULL :
		CONST_PTR_OFFSET(cache->mmap_base, offset);
	return mail_cache_map_finish(cache, offset, size,
				     cache->mmap_base, FALSE, corrupted_r);
}

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size,
		   const void **data_r)
{
	i_assert(offset != 0);

	bool corrupted;
	int ret = mail_cache_map_full(cache, offset, size, data_r, &corrupted);
	i_assert(!corrupted);
	return ret;
}

int mail_cache_map_all(struct mail_cache *cache)
{
	const void *data;
	bool corrupted;

	int ret = mail_cache_map_full(cache, 0, 0, &data, &corrupted);
	i_assert(ret != 0);
	if (corrupted) {
		i_assert(ret == -1);
		return 0;
	}
	return ret < 0 ? -1 : 1;
}

int mail_cache_open_and_verify(struct mail_cache *cache)
{
	int ret;

	if (cache->opened) {
		if (!MAIL_CACHE_IS_UNUSABLE(cache))
			return 1;
		mail_cache_file_close(cache);
	}
	if ((ret = mail_cache_try_open(cache)) < 0) {
		/* I/O error */
		mail_cache_file_close(cache);
		return -1;
	}

	if (ret > 0) {
		if (mail_cache_header_fields_read(cache) < 0) {
			/* corrupted */
			ret = 0;
		}
	}
	if (ret == 0) {
		/* cache was corrupted and should have been deleted already. */
		mail_cache_file_close(cache);
	}
	return ret;
}

struct mail_cache *
mail_cache_open_or_create_path(struct mail_index *index, const char *path)
{
	struct mail_cache *cache;

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
	cache->filepath = i_strdup(path);
	cache->field_pool = pool_alloconly_create("Cache fields", 2048);
	hash_table_create(&cache->field_name_hash, cache->field_pool, 0,
			  strcase_hash, strcasecmp);

	cache->event = event_create(index->event);
	event_add_category(cache->event, &event_category_mail_cache);
	event_set_append_log_prefix(cache->event,
		t_strdup_printf("Cache %s: ", cache->filepath));

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
	const char *path = t_strconcat(index->filepath,
				       MAIL_CACHE_FILE_SUFFIX, NULL);
	return mail_cache_open_or_create_path(index, path);
}

void mail_cache_free(struct mail_cache **_cache)
{
	struct mail_cache *cache = *_cache;

	*_cache = NULL;

	i_assert(cache->views == NULL);

	if (cache->file_cache != NULL)
		file_cache_free(&cache->file_cache);

	mail_index_unregister_expunge_handler(cache->index, cache->ext_id);
	mail_cache_file_close(cache);

	buffer_free(&cache->read_buf);
	hash_table_destroy(&cache->field_name_hash);
	pool_unref(&cache->field_pool);
	event_unref(&cache->event);
	i_free(cache->field_file_map);
	i_free(cache->file_field_map);
	i_free(cache->fields);
	i_free(cache->filepath);
	i_free(cache);
}

static int mail_cache_lock_file(struct mail_cache *cache)
{
	unsigned int timeout_secs;
	bool nonblock = FALSE;
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
	if (cache->file_lock != NULL)
		file_unlock(&cache->file_lock);
}

static bool
mail_cache_verify_reset_id(struct mail_cache *cache, uint32_t *reset_id_r)
{
	const struct mail_index_ext *ext;
	struct mail_index_view *iview;
	uint32_t reset_id;

	iview = mail_index_view_open(cache->index);
	ext = mail_index_view_get_ext(iview, cache->ext_id);
	reset_id = ext == NULL ? 0 : ext->reset_id;
	mail_index_view_close(&iview);

	*reset_id_r = reset_id;
	return cache->hdr->file_seq == reset_id;
}

static int
mail_cache_sync_wait_index(struct mail_cache *cache, uint32_t *reset_id_r)
{
	const char *lock_reason = "cache reset_id sync";
	uint32_t file_seq;
	uoff_t file_offset;
	bool cache_locked = cache->file_lock != NULL;
	int ret;

	if (cache->index->log_sync_locked)
		return 0;

	/* Wait for .log file lock, so we can be sure that there is no cache
	   purging going on. (Because it first recreates the cache file,
	   unlocks it and only then writes the changes to the index and
	   releases the .log lock.) To prevent deadlocks, cache file must be
	   locked after the .log, not before. */
	if (cache_locked)
		mail_cache_unlock_file(cache);
	if (mail_transaction_log_sync_lock(cache->index->log, lock_reason,
					   &file_seq, &file_offset) < 0)
		return -1;
	/* Lock the cache file as well so we'll get a guaranteed result on
	   whether the reset_id can be synced or if it's already desynced and
	   the cache just needs to be recreated. */
	ret = -1;
	while (mail_cache_lock_file(cache) > 0) {
		/* Locked the current fd, but it may have already been
		   recreated. Reopen and retry if needed. */
		if (!mail_cache_need_reopen(cache)) {
			ret = 1;
			break;
		}
		if ((ret = mail_cache_reopen(cache)) <= 0)
			break;
	}

	if (ret <= 0)
		;
	else if (mail_index_refresh(cache->index) < 0)
		ret = -1;
	else
		ret = mail_cache_verify_reset_id(cache, reset_id_r) ? 1 : 0;
	mail_transaction_log_sync_unlock(cache->index->log, lock_reason);
	if (ret <= 0 || !cache_locked)
		mail_cache_unlock_file(cache);
	return ret;
}

int mail_cache_sync_reset_id(struct mail_cache *cache)
{
	uint32_t reset_id;
	int ret;

	/* verify that the index reset_id matches the cache's file_seq */
	if (mail_cache_verify_reset_id(cache, &reset_id))
		return 1;

	/* Mismatch. See if we can get it synced. */
	if (cache->index->mapping) {
		/* Syncing is already locked, and we're in the middle of
		   mapping the index. The cache is unusable. */
		i_assert(cache->index->log_sync_locked);
		mail_cache_set_corrupted(cache, "reset_id mismatch during sync");
		return 0;
	}

	/* See if reset_id changes after refreshing the index. */
	if (mail_index_refresh(cache->index) < 0)
		return -1;
	if (mail_cache_verify_reset_id(cache, &reset_id))
		return 1;

	/* Use locking to wait for a potential cache purging to finish.
	   If that didn't work either, the cache is corrupted or lost. */
	ret = mail_cache_sync_wait_index(cache, &reset_id);
	if (ret == 0 && cache->fd != -1 && reset_id != 0) {
		mail_cache_set_corrupted(cache,
			"reset_id mismatch even after locking "
			"(file_seq=%u != reset_id=%u)",
			cache->hdr == NULL ? 0 : cache->hdr->file_seq,
			reset_id);
	}
	return ret;
}

int mail_cache_lock(struct mail_cache *cache)
{
	int ret;

	i_assert(!cache->locked);
	/* the only reason why we might be in here while mapping the index is
	   if we're coming from mail_cache_expunge_count() while syncing the
	   index. */
	i_assert(!cache->index->mapping || cache->index->log_sync_locked);

	if (MAIL_INDEX_IS_IN_MEMORY(cache->index) ||
	    cache->index->readonly)
		return 0;

	/* Make sure at least some cache file is opened. Usually it's the
	   latest one, so delay until it's locked to check whether a newer
	   cache file exists. */
	if ((ret = mail_cache_open_and_verify(cache)) < 0)
		return -1;
	if (ret == 0) {
		/* Cache doesn't exist or it was just found to be corrupted and
		   was unlinked. Cache purging will create it back. */
		return 0;
	}

	for (;;) {
		if (mail_cache_lock_file(cache) <= 0)
			return -1;
		if (!mail_cache_need_reopen(cache)) {
			/* locked the latest file */
			break;
		}
		if ((ret = mail_cache_reopen(cache)) <= 0) {
			i_assert(cache->file_lock == NULL);
			return ret;
		}
		i_assert(cache->file_lock == NULL);
		/* okay, so it was just purged. try again. */
	}

	if ((ret = mail_cache_sync_reset_id(cache)) <= 0) {
		mail_cache_unlock_file(cache);
		return ret;
	}
	i_assert(cache->file_lock != NULL);

	/* successfully locked - make sure our header is up to date */
	cache->locked = TRUE;
	cache->hdr_modified = FALSE;

	if (cache->file_cache != NULL) {
		file_cache_invalidate(cache->file_cache, 0,
				      sizeof(struct mail_cache_header));
	}
	if (cache->read_buf != NULL)
		buffer_set_used_size(cache->read_buf, 0);
	if ((ret = mail_cache_map_all(cache)) <= 0) {
		mail_cache_unlock(cache);
		return ret;
	}
	cache->hdr_copy = *cache->hdr;
	return 1;
}

int mail_cache_flush_and_unlock(struct mail_cache *cache)
{
	int ret = 0;

	i_assert(cache->locked);

	if (cache->field_header_write_pending)
                ret = mail_cache_header_fields_update(cache);

	/* Cache may become unusable during for various reasons, e.g.
	   mail_cache_map(). Also the above mail_cache_header_fields_update()
	   call can make it unusable, so check this after it. */
	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		mail_cache_unlock(cache);
		return -1;
	}

	if (cache->hdr_modified) {
		cache->hdr_modified = FALSE;
		if (mail_cache_write(cache, &cache->hdr_copy,
				     sizeof(cache->hdr_copy), 0) < 0)
			ret = -1;
		cache->hdr_ro_copy = cache->hdr_copy;
		mail_cache_update_need_purge(cache);
	}

	mail_cache_unlock(cache);
	return ret;
}

void mail_cache_unlock(struct mail_cache *cache)
{
	i_assert(cache->locked);

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		/* we found it to be broken during the lock. just clean up. */
		cache->hdr_modified = FALSE;
	} else if (cache->index->fsync_mode == FSYNC_MODE_ALWAYS) {
		if (fdatasync(cache->fd) < 0)
			mail_cache_set_syscall_error(cache, "fdatasync()");
	}

	cache->locked = FALSE;
	mail_cache_unlock_file(cache);
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
	DLLIST_PREPEND(&cache->views, view);
	return view;
}

void mail_cache_view_close(struct mail_cache_view **_view)
{
	struct mail_cache_view *view = *_view;

	i_assert(view->trans_view == NULL);

	*_view = NULL;
	if (view->cache->field_header_write_pending &&
	    !view->cache->purging)
                (void)mail_cache_header_fields_update(view->cache);

	DLLIST_REMOVE(&view->cache->views, view);
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
		return idx_hdr->messages_count+1;
	}
	return first_new_seq;
}
