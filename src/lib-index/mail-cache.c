/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "file-lock.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-cache-private.h"

#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>

unsigned int mail_cache_field_sizes[32] = {
	sizeof(enum mail_index_record_flag),
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

#if 0
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

	cache->used_file_size = nbo_to_uint32(hdr->used_file_size);

	/* only check the header if we're locked */
	if (cache->locks == 0)
		return 1;

	if (cache->used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return 0;
	}
	if ((cache->used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return 0;
	}

	if (cache->used_file_size > cache->mmap_length) {
		/* maybe a crash truncated the file - just fix it */
		hdr->used_file_size = uint32_to_nbo(cache->mmap_length & ~3);
		if (msync(cache->mmap_base, sizeof(*hdr), MS_SYNC) < 0) {
			mail_cache_set_syscall_error(cache, "msync()");
			return -1;
		}
	}
	return 1;
}

static int mmap_update_nocheck(struct mail_cache *cache,
			       size_t offset, size_t size)
{
	struct stat st;

	/* if sequence has changed, the file has to be reopened.
	   note that if main index isn't locked, it may change again */
	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq &&
	    cache->mmap_base != NULL) {
		if (!mail_cache_file_reopen(cache))
			return -1;
	}

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

static int mmap_update(struct mail_cache *cache, size_t offset, size_t size)
{
	int synced, ret;

	for (synced = FALSE;; synced = TRUE) {
		ret = mmap_update_nocheck(cache, offset, size);
		if (ret > 0)
			return TRUE;
		if (ret < 0)
			return FALSE;

		if (!mmap_verify_header(cache))
			return FALSE;

		/* see if cache file was rebuilt - do it only once to avoid
		   infinite looping */
		if (cache->hdr->sync_id == cache->index->cache_sync_id ||
		    synced)
			break;

		if (!mail_cache_file_reopen(cache))
			return FALSE;
	}
	return TRUE;
}

static int mail_cache_open_and_verify(struct mail_cache *cache, int silent)
{
	struct stat st;

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
	if (!mmap_verify_header(cache)) {
		cache->silent = FALSE;
		return 0;
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
		return ret > 0;

	/* we'll have to clear cache_offsets which requires exclusive lock */
	if (!mail_index_set_lock(cache->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* maybe a rebuild.. */
	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return FALSE;
	}

	/* see if someone else just created the cache file */
	ret = mail_cache_open_and_verify(cache, TRUE);
	if (ret != 0) {
		(void)file_dotlock_delete(cache->filepath, fd);
		return ret > 0;
	}

	/* rebuild then */
	if (write_full(fd, hdr, sizeof(*hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}

	if (cache->index->hdr.cache_file_seq != 0) {
		// FIXME: recreate index file with cache_offsets cleared
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return FALSE;
	}

	if (!mmap_update(cache, 0, sizeof(struct mail_cache_header)))
		return FALSE;

	return TRUE;
}

int mail_cache_open_or_create(struct mail_index *index)
{
        struct mail_cache_header hdr;
	struct mail_cache *cache;

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = index->indexid;
	hdr.sync_id = index->hdr->cache_file_seq; // FIXME
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
        cache->split_header_pool = pool_alloconly_create("Headers", 512);

	index->cache = cache;

	/* we'll do anon-mmaping only if initially requested. if we fail
	   because of out of disk space, we'll just let the main index code
	   know it and fail. */
	if (!mail_cache_open_or_create_file(cache, &hdr)) {
		mail_cache_free(cache);
		return FALSE;
	}

	return TRUE;
}

void mail_cache_free(struct mail_cache *cache)
{
	i_assert(cache->trans_ctx == NULL);

	cache->index->cache = NULL;

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
	int ret, fd;

	i_assert(cache->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = cache->index->indexid;
	hdr.sync_id = cache->sync_id = cache->index->cache_sync_id =
		++cache->index->hdr->cache_sync_id;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));
	cache->used_file_size = sizeof(hdr);

	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return -1;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return -1;
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return -1;
	}

	cache->mmap_refresh = TRUE;
	if (!mmap_update(cache, 0, sizeof(struct mail_cache_header)))
		return -1;

	return 0;
}

int mail_cache_lock(struct mail_cache *cache, int nonblock)
{
	int ret;

	if (cache->locks++ != 0)
		return TRUE;

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
		if (!mmap_update(cache, 0, 0)) {
			(void)mail_cache_unlock(cache);
			return -1;
		}
		if (cache->sync_id != cache->index->cache_sync_id) {
			/* we have the cache file locked and sync_id still
			   doesn't match. it means we crashed between updating
			   cache file and updating sync_id in index header.
			   just update the sync_ids so they match. */
			i_warning("Updating broken sync_id in cache file %s",
				  cache->filepath);
			cache->sync_id = cache->hdr->sync_id =
				cache->index->cache_sync_id;
		}
	}
	return ret;
}

int mail_cache_unlock(struct mail_cache *cache)
{
	if (--cache->locks > 0)
		return TRUE;

	if (file_wait_lock(cache->fd, F_UNLCK) <= 0) {
		mail_cache_set_syscall_error(cache, "file_wait_lock(F_UNLCK)");
		return FALSE;
	}

	return TRUE;
}

int mail_cache_is_locked(struct mail_cache *cache)
{
	return cache->locks > 0;
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
#else

int mail_cache_open_or_create(struct mail_index *index)
{
	return 0;
}

void mail_cache_free(struct mail_cache *cache)
{
}

void mail_cache_set_defaults(struct mail_cache *cache,
			     enum mail_cache_field default_cache_fields,
			     enum mail_cache_field never_cache_fields) {}

/* Compress cache file. */
int mail_cache_compress(struct mail_cache *cache) {return 0;}

/* Reset the cache file, clearing all data. */
int mail_cache_reset(struct mail_cache *cache) {return 0;}

/* Explicitly lock the cache file. Returns 1 if ok, 0 if nonblock is TRUE and
   we couldn't immediately get a lock, or -1 if error. */
int mail_cache_lock(struct mail_cache *cache, int nonblock) {return 0;}
int mail_cache_unlock(struct mail_cache *cache) {return 0;}

/* Returns TRUE if cache file is locked. */
int mail_cache_is_locked(struct mail_cache *cache) {return TRUE;}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview)
{return i_new(struct mail_cache_view, 1);}
void mail_cache_view_close(struct mail_cache_view *view) {i_free(view);}

/* Begin transaction. Cache transaction may be committed or rollbacked multiple
   times. It will finish when index transaction is committed or rollbacked.
   The transaction might also be partially committed automatically, so this
   is kind of fake transaction, it's only purpose being optimizing writes.
   Returns same as mail_cache_lock(). */
int mail_cache_transaction_begin(struct mail_cache_view *view, int nonblock,
				 struct mail_index_transaction *t,
				 struct mail_cache_transaction_ctx **ctx_r)
{
	*ctx_r = NULL;
	return 1;
}
int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx)
{return 0;}
void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx) {}

/* Should be called only by mail_transaction_commit/rollback: */
int mail_cache_transaction_end(struct mail_cache_transaction_ctx *ctx)
{return 0;}

/* Return NULL-terminated list of headers for given index, or NULL if
   header index isn't used. */
const char *const *mail_cache_get_header_fields(struct mail_cache_view *view,
						unsigned int idx)
{return NULL;}
/* Set list of headers for given index. */
int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[])
{return 0;}

/* Add new field to given record. Updates are not allowed. Fixed size fields
   must be exactly the expected size and they're converted to network byte
   order in disk. */
int mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		   enum mail_cache_field field,
		   const void *data, size_t data_size)
{return 0;}

/* Mark the given record deleted. */
int mail_cache_delete(struct mail_cache_transaction_ctx *ctx, uint32_t seq)
{return 0;}

/* Return all fields that are currently cached for record. */
enum mail_cache_field
mail_cache_get_fields(struct mail_cache_view *view, uint32_t seq) {return 0;}

/* Set data_r and size_r to point to wanted field in cache file.
   Returns TRUE if field was found. If field contains multiple fields,
   first one found is returned. This is mostly useful for finding headers. */
int mail_cache_lookup_field(struct mail_cache_view *view, uint32_t seq,
			    enum mail_cache_field field,
			    const void **data_r, size_t *size_r) {return 0;}

/* Return string field. */
const char *
mail_cache_lookup_string_field(struct mail_cache_view *view, uint32_t seq,
			       enum mail_cache_field field) {return 0;}

/* Copy fixed size field to given buffer. buffer_size must be exactly the
   expected size. The result will be converted to host byte order.
   Returns TRUE if field was found. */
int mail_cache_copy_fixed_field(struct mail_cache_view *view, uint32_t seq,
				enum mail_cache_field field,
				void *buffer, size_t buffer_size) {return 0;}

/* Mark given fields as missing, ie. they should be cached when possible. */
void mail_cache_mark_missing(struct mail_cache_view *view,
			     enum mail_cache_field fields) {}

/* Return index flags. */
enum mail_index_record_flag
mail_cache_get_index_flags(struct mail_cache_view *view, uint32_t seq)
{return 0;}

/* Update index flags. The cache file must be locked and the flags must be
   already inserted to the record. */
int mail_cache_update_index_flags(struct mail_cache_view *view, uint32_t seq,
				  enum mail_index_record_flag flags)
{return 0;}

/* Update location offset. External locking is assumed to take care of locking
   readers out to prevent race conditions. */
int mail_cache_update_location_offset(struct mail_cache_view *view,
				      uint32_t seq, uoff_t offset)
{return 0;}

/* "Error in index cache file %s: ...". */
void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
{}

#endif
