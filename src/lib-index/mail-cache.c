/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "ioloop.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>

/* Never compress the file if it's smaller than this */
#define COMPRESS_MIN_SIZE (1024*50)

/* Compress the file when deleted space reaches n% of total size */
#define COMPRESS_PERCENTAGE 20

/* Compress the file when n% of rows contain continued rows.
   200% means that there's 2 continued rows per record. */
#define COMPRESS_CONTINUED_PERCENTAGE 200

/* Initial size for the file */
#define MAIL_CACHE_INITIAL_SIZE (sizeof(struct mail_cache_header) + 10240)

/* When more space is needed, grow the file n% larger than the previous size */
#define MAIL_CACHE_GROW_PERCENTAGE 10

#define MAIL_CACHE_LOCK_TIMEOUT 120
#define MAIL_CACHE_LOCK_CHANGE_TIMEOUT 60
#define MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT (5*60)

#define CACHE_RECORD(cache, offset) \
	((struct mail_cache_record *) ((char *) (cache)->mmap_base + offset))

struct mail_cache_header {
	uint32_t indexid;
	uint32_t sync_id;

	uint32_t continued_record_count;

	uint32_t used_file_size;
	uint32_t deleted_space;

	uint32_t used_fields; /* enum mail_cache_field */

	uint32_t field_usage_start; /* time_t */
	uint32_t field_usage_counts[32];

	uint32_t header_offsets[MAIL_CACHE_HEADERS_COUNT];
};

struct mail_cache_record {
	uint32_t fields; /* enum mail_cache_field */
	uint32_t next_offset;
	uint32_t size; /* full record size, including this header */
};

struct mail_cache {
	struct mail_index *index;

	char *filepath;
	int fd;

	void *mmap_base;
	size_t mmap_length;
	uint32_t used_file_size;
	uint32_t sync_id;

	struct mail_cache_header *header;

	pool_t split_header_pool;
	uint32_t split_offsets[MAIL_CACHE_HEADERS_COUNT];
	const char *const *split_headers[MAIL_CACHE_HEADERS_COUNT];

	enum mail_cache_field default_cache_fields;
	enum mail_cache_field never_cache_fields;

        struct mail_cache_transaction_ctx *trans_ctx;
	unsigned int locks;

	unsigned int anon_mmap:1;
	unsigned int mmap_refresh:1;
	unsigned int silent:1;
};

struct mail_cache_transaction_ctx {
	struct mail_cache *cache;

	unsigned int next_unused_header_lowwater;

	unsigned int last_idx;
	struct mail_cache_record cache_rec;
	buffer_t *cache_data;

	unsigned int first_uid, last_uid, prev_uid;
	enum mail_cache_field prev_fields;
	buffer_t *index_marks, *cache_marks;
};

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

static const unsigned char *null4[] = { 0, 0, 0, 0 };

static const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx);
static int mail_cache_write(struct mail_cache_transaction_ctx *ctx);
static struct mail_cache_record *
mail_cache_lookup(struct mail_cache *cache,
		  const struct mail_index_record *rec,
		  enum mail_cache_field fields);

static uint32_t uint32_to_offset(uint32_t offset)
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

static uint32_t offset_to_uint32(uint32_t offset)
{
	const unsigned char *buf = (const unsigned char *) &offset;

	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return (((uint32_t)buf[3] & 0x7f) << 2) |
		(((uint32_t)buf[2] & 0x7f) << 9) |
		(((uint32_t)buf[1] & 0x7f) << 16) |
		(((uint32_t)buf[0] & 0x7f) << 23);
}

static int mail_cache_set_syscall_error(struct mail_cache *cache,
					const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		cache->index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(cache->index, "%s failed with index cache file %s: %m",
			function, cache->filepath);
	return FALSE;
}

static int mail_cache_create_memory(struct mail_cache *cache,
				    struct mail_cache_header *hdr)
{
	cache->mmap_length = MAIL_CACHE_INITIAL_SIZE;
	cache->mmap_base = mmap_anon(cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		index_set_error(cache->index, "mmap_anon(%"PRIuSIZE_T")",
				cache->mmap_length);
		return FALSE;
	}

	cache->header = cache->mmap_base;
	*cache->header = *hdr;

	cache->anon_mmap = TRUE;
	cache->filepath = i_strdup_printf("(in-memory index cache for %s)",
					  cache->index->mailbox_path);
	return TRUE;
}

static void mail_cache_file_close(struct mail_cache *cache)
{
	if (cache->anon_mmap) {
		if (munmap_anon(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap_anon()");
	} else if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	cache->mmap_base = NULL;
	cache->header = NULL;
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

	if (cache->anon_mmap) {
		/* cache was set corrupted, we'll have to quit */
		return FALSE;
	}

	fd = open(cache->filepath, O_RDWR);
	if (fd == -1)
		return mail_cache_set_syscall_error(cache, "open()");

	mail_cache_file_close(cache);

	cache->fd = fd;
	return TRUE;
}

static int mmap_verify_header(struct mail_cache *cache)
{
	struct mail_cache_header *hdr;

	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header))
		return mail_cache_set_corrupted(cache, "File too small");
	cache->header = hdr = cache->mmap_base;
	cache->sync_id = hdr->sync_id;

	if (cache->header->indexid != cache->index->indexid) {
		/* index id changed */
		if (cache->header->indexid != 0)
			mail_cache_set_corrupted(cache, "indexid changed");
		cache->index->inconsistent = TRUE; /* easiest way to rebuild */
		return FALSE;
	}

	if (cache->trans_ctx != NULL) {
		/* we've updated used_file_size, do nothing */
		return TRUE;
	}

	cache->used_file_size = nbo_to_uint32(hdr->used_file_size);

	/* only check the header if we're locked */
	if (cache->locks == 0)
		return TRUE;

	if (cache->used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return FALSE;
	}
	if ((cache->used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return FALSE;
	}

	if (cache->used_file_size > cache->mmap_length) {
		/* maybe a crash truncated the file - just fix it */
		hdr->used_file_size = uint32_to_nbo(cache->mmap_length & ~3);
		if (msync(cache->mmap_base, sizeof(*hdr), MS_SYNC) < 0) 
			return mail_cache_set_syscall_error(cache, "msync()");
	}
	return TRUE;
}

static int mmap_update_nocheck(struct mail_cache *cache,
			       size_t offset, size_t size)
{
	struct stat st;

	/* if sync id has changed, the file has to be reopened.
	   note that if main index isn't locked, it may change again */
	if (cache->sync_id != cache->index->cache_sync_id &&
	    cache->mmap_base != NULL) {
		if (!mail_cache_file_reopen(cache))
			return -1;
	}

	if (offset < cache->mmap_length &&
	    size <= cache->mmap_length - offset &&
	    !cache->mmap_refresh) {
		/* already mapped */
		if (size != 0 || cache->anon_mmap)
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

	if (cache->anon_mmap)
		return 1;

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
	cache->header = NULL;
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
		if (cache->header->sync_id == cache->index->cache_sync_id ||
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

static void mail_index_clear_cache_offsets(struct mail_index *index)
{
	struct mail_index_record *rec;

	index->sync_stamp = 0;

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		rec->cache_offset = 0;
		rec = index->next(index, rec);
	}
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
	cache->index->inconsistent = FALSE;
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

	mail_index_clear_cache_offsets(cache->index);

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return FALSE;
	}

	cache->mmap_refresh = TRUE;
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
	hdr.sync_id = index->cache_sync_id;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
        cache->split_header_pool = pool_alloconly_create("Headers", 512);

	index->cache = cache;

	/* we'll do anon-mmaping only if initially requested. if we fail
	   because of out of disk space, we'll just let the main index code
	   know it and fail. */
	if (INDEX_IS_IN_MEMORY(index)) {
		if (!mail_cache_create_memory(cache, &hdr)) {
			mail_cache_free(cache);
			return FALSE;
		}
	} else {
		if (!mail_cache_open_or_create_file(cache, &hdr)) {
			mail_cache_free(cache);
			return FALSE;
		}
	}

	/* unset inconsistency - we already rebuilt the cache file */
	index->inconsistent = FALSE;

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

static const struct mail_cache_record *
mail_cache_compress_record(struct mail_cache *cache,
			   struct mail_index_record *rec, int header_idx,
			   uint32_t *size_r)
{
	enum mail_cache_field orig_cached_fields, cached_fields, field;
	struct mail_cache_record cache_rec;
	buffer_t *buffer;
	const void *data;
	size_t size, pos;
	uint32_t nb_size;
	int i;

	memset(&cache_rec, 0, sizeof(cache_rec));
	buffer = buffer_create_dynamic(pool_datastack_create(),
				       4096, (size_t)-1);

        orig_cached_fields = mail_cache_get_fields(cache, rec);
	cached_fields = orig_cached_fields & ~MAIL_CACHE_HEADERS_MASK;
	buffer_append(buffer, &cache_rec, sizeof(cache_rec));
	for (i = 0, field = 1; i < 31; i++, field <<= 1) {
		if ((cached_fields & field) == 0)
			continue;

		if (!mail_cache_lookup_field(cache, rec, field, &data, &size)) {
			cached_fields &= ~field;
			continue;
		}

		nb_size = uint32_to_nbo((uint32_t)size);

		if ((field & MAIL_CACHE_FIXED_MASK) == 0)
			buffer_append(buffer, &nb_size, sizeof(nb_size));
		buffer_append(buffer, data, size);
		if ((size & 3) != 0)
			buffer_append(buffer, null4, 4 - (size & 3));
	}

	/* now merge all the headers if we have them all */
	if ((orig_cached_fields & mail_cache_header_fields[header_idx]) != 0) {
		nb_size = 0;
		pos = buffer_get_used_size(buffer);
		buffer_append(buffer, &nb_size, sizeof(nb_size));

		for (i = 0; i <= header_idx; i++) {
			field = mail_cache_header_fields[i];
			if (mail_cache_lookup_field(cache, rec, field,
						    &data, &size) && size > 1) {
				size--; /* terminating \0 */
				buffer_append(buffer, data, size);
				nb_size += size;
			}
		}
		buffer_append(buffer, "", 1);
		nb_size++;
		if ((nb_size & 3) != 0)
			buffer_append(buffer, null4, 4 - (nb_size & 3));

		nb_size = uint32_to_nbo(nb_size);
		buffer_write(buffer, pos, &nb_size, sizeof(nb_size));

		cached_fields |= MAIL_CACHE_HEADERS1;
	}

	cache_rec.fields = cached_fields;
	cache_rec.size = uint32_to_nbo(buffer_get_used_size(buffer));
	buffer_write(buffer, 0, &cache_rec, sizeof(cache_rec));

	data = buffer_get_data(buffer, &size);
	*size_r = size;
	return data;
}

static int mail_cache_copy(struct mail_cache *cache, int fd)
{
	struct mail_cache_header *hdr;
	const struct mail_cache_record *cache_rec;
	struct mail_index_record *rec;
        enum mail_cache_field used_fields;
	unsigned char *mmap_base;
	const char *str;
	uint32_t new_file_size, offset, size, nb_size;
	int i, header_idx;

	/* pick some reasonably good file size */
	new_file_size = cache->used_file_size -
		nbo_to_uint32(cache->header->deleted_space);
	new_file_size = (new_file_size + 1023) & ~1023;
	if (new_file_size < MAIL_CACHE_INITIAL_SIZE)
		new_file_size = MAIL_CACHE_INITIAL_SIZE;

	if (file_set_size(fd, new_file_size) < 0)
		return mail_cache_set_syscall_error(cache, "file_set_size()");

	mmap_base = mmap(NULL, new_file_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);
	if (mmap_base == MAP_FAILED)
		return mail_cache_set_syscall_error(cache, "mmap()");

	/* skip file's header */
	hdr = (struct mail_cache_header *) mmap_base;
	offset = sizeof(*hdr);

	/* merge all the header pieces into one. if some message doesn't have
	   all the required pieces, we'll just have to drop them all. */
	for (i = MAIL_CACHE_HEADERS_COUNT-1; i >= 0; i--) {
		str = mail_cache_get_header_fields_str(cache, i);
		if (str != NULL)
			break;
	}

	if (str == NULL)
		header_idx = -1;
	else {
		hdr->header_offsets[0] = uint32_to_offset(offset);
		header_idx = i;

		size = strlen(str) + 1;
		nb_size = uint32_to_nbo(size);

		memcpy(mmap_base + offset, &nb_size, sizeof(nb_size));
		offset += sizeof(nb_size);
		memcpy(mmap_base + offset, str, size);
		offset += (size + 3) & ~3;
	}

	used_fields = 0;
	rec = cache->index->lookup(cache->index, 1);
	while (rec != NULL) {
		cache_rec = mail_cache_lookup(cache, rec, 0);
		if (cache_rec == NULL)
			rec->cache_offset = 0;
		else if (offset_to_uint32(cache_rec->next_offset) == 0) {
			/* just one unmodified block, copy it */
			size = nbo_to_uint32(cache_rec->size);
			i_assert(offset + size <= new_file_size);

			memcpy(mmap_base + offset, cache_rec, size);
			rec->cache_offset = uint32_to_offset(offset);

			size = (size + 3) & ~3;
			offset += size;
		} else {
			/* multiple blocks, sort them into buffer */
			t_push();
			cache_rec = mail_cache_compress_record(cache, rec,
							       header_idx,
							       &size);
			i_assert(offset + size <= new_file_size);
			memcpy(mmap_base + offset, cache_rec, size);
			used_fields |= cache_rec->fields;
			t_pop();

			rec->cache_offset = uint32_to_offset(offset);
			offset += size;
		}

		rec = cache->index->next(cache->index, rec);
	}

	/* update header */
	hdr->indexid = cache->index->indexid;
	hdr->sync_id = cache->sync_id = cache->index->cache_sync_id =
		++cache->index->header->cache_sync_id;
	hdr->used_file_size = uint32_to_nbo(offset);
	hdr->used_fields = used_fields;
	hdr->field_usage_start = uint32_to_nbo(ioloop_time);

	/* write everything to disk */
	if (msync(mmap_base, offset, MS_SYNC) < 0)
		return mail_cache_set_syscall_error(cache, "msync()");

	if (munmap(mmap_base, new_file_size) < 0)
		return mail_cache_set_syscall_error(cache, "munmap()");

	if (fdatasync(fd) < 0)
		return mail_cache_set_syscall_error(cache, "fdatasync()");
	return TRUE;
}

int mail_cache_compress(struct mail_cache *cache)
{
	int fd, ret = TRUE;

	i_assert(cache->trans_ctx == NULL);

	if (cache->anon_mmap)
		return TRUE;

	if (!cache->index->set_lock(cache->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (mail_cache_lock(cache, TRUE) <= 0)
		return FALSE;

#ifdef DEBUG
	i_warning("Compressing cache file %s", cache->filepath);
#endif

	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return FALSE;
	}

	/* now we'll begin the actual moving. keep rebuild-flag on
	   while doing it. */
	cache->index->header->flags |= MAIL_INDEX_HDR_FLAG_REBUILD;
	if (!mail_index_fmdatasync(cache->index, cache->index->header_size))
		return FALSE;

	if (!mail_cache_copy(cache, fd)) {
		(void)file_dotlock_delete(cache->filepath, fd);
		ret = FALSE;
	} else {
		mail_cache_file_close(cache);
		cache->fd = dup(fd);

		if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
			mail_cache_set_syscall_error(cache,
						     "file_dotlock_replace()");
			ret = FALSE;
		}

		if (!mmap_update(cache, 0, 0))
			ret = FALSE;
	}

	/* headers could have changed, reread them */
	memset(cache->split_offsets, 0, sizeof(cache->split_offsets));
	memset(cache->split_headers, 0, sizeof(cache->split_headers));

	if (ret) {
		cache->index->header->flags &=
			~(MAIL_INDEX_HDR_FLAG_REBUILD |
			  MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE);
	}

	if (!mail_cache_unlock(cache))
		ret = FALSE;

	return ret;
}

int mail_cache_truncate(struct mail_cache *cache)
{
	struct mail_cache_header hdr;
	int ret, fd;

	i_assert(cache->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = cache->index->indexid;
	hdr.sync_id = cache->sync_id = cache->index->cache_sync_id =
		++cache->index->header->cache_sync_id;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));
	cache->used_file_size = sizeof(hdr);

	if (cache->anon_mmap) {
		*cache->header = hdr;
		return TRUE;
	}

	ret = mail_cache_open_and_verify(cache, TRUE);
	if (ret != 0)
		return ret > 0;

	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return FALSE;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return FALSE;
	}

	cache->mmap_refresh = TRUE;
	if (!mmap_update(cache, 0, sizeof(struct mail_cache_header)))
		return FALSE;

	return TRUE;
}

int mail_cache_mark_file_deleted(struct mail_cache *cache)
{
	uint32_t indexid = 0;

	if (cache->anon_mmap)
		cache->header->indexid = 0;
	else {
		if (pwrite(cache->fd, &indexid, sizeof(indexid), 0) < 0)
			return mail_cache_set_syscall_error(cache, "pwrite()");
	}
	return TRUE;
}

int mail_cache_lock(struct mail_cache *cache, int nonblock)
{
	int ret;

	if (cache->locks++ != 0)
		return TRUE;

	if (cache->anon_mmap)
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
			cache->sync_id = cache->header->sync_id =
				cache->index->cache_sync_id;
		}
	}
	return ret;
}

int mail_cache_unlock(struct mail_cache *cache)
{
	if (--cache->locks > 0)
		return TRUE;

	if (cache->anon_mmap)
		return TRUE;

	if (file_wait_lock(cache->fd, F_UNLCK) <= 0) {
		mail_cache_set_syscall_error(cache, "file_wait_lock(F_UNLCK)");
		return FALSE;
	}

	return TRUE;
}

void mail_cache_unlock_later(struct mail_cache *cache)
{
	cache->index->cache_later_locks++;
}

int mail_cache_is_locked(struct mail_cache *cache)
{
	return cache->locks > 0;
}

int mail_cache_transaction_begin(struct mail_cache *cache, int nonblock,
				 struct mail_cache_transaction_ctx **ctx_r)
{
	int ret;

	i_assert(cache->trans_ctx == NULL);

	ret = mail_cache_lock(cache, nonblock);
	if (ret <= 0)
		return ret;

	*ctx_r = i_new(struct mail_cache_transaction_ctx, 1);
	(*ctx_r)->cache = cache;
	(*ctx_r)->cache_data =
		buffer_create_dynamic(system_pool, 8192, (size_t)-1);
	(*ctx_r)->last_idx = (unsigned int)-1;

	cache->trans_ctx = *ctx_r;
	return 1;
}

int mail_cache_transaction_end(struct mail_cache_transaction_ctx *ctx)
{
	int ret = TRUE;

	i_assert(ctx->cache->trans_ctx != NULL);

	(void)mail_cache_transaction_rollback(ctx);

	if (!mail_cache_unlock(ctx->cache))
		ret = FALSE;

	ctx->cache->trans_ctx = NULL;

	if (ctx->cache_marks != NULL)
		buffer_free(ctx->cache_marks);
	if (ctx->index_marks != NULL)
		buffer_free(ctx->index_marks);
	buffer_free(ctx->cache_data);
	i_free(ctx);
	return ret;
}

static void mail_cache_transaction_flush(struct mail_cache_transaction_ctx *ctx)
{
	memset(&ctx->cache_rec, 0, sizeof(ctx->cache_rec));
	ctx->last_idx = (unsigned int)-1;

	ctx->next_unused_header_lowwater = 0;
	ctx->first_uid = ctx->last_uid = ctx->prev_uid = 0;
	ctx->prev_fields = 0;

	if (ctx->cache_marks != NULL)
		buffer_set_used_size(ctx->cache_marks, 0);
	if (ctx->index_marks != NULL)
		buffer_set_used_size(ctx->index_marks, 0);
	buffer_set_used_size(ctx->cache_data, 0);
}

static void mark_update(buffer_t **buf, uint32_t offset, uint32_t data)
{
	if (*buf == NULL)
		*buf = buffer_create_dynamic(system_pool, 1024, (size_t)-1);

	/* data is in big endian, we want to update only the lowest byte */
	buffer_append(*buf, &offset, sizeof(offset));
	buffer_append(*buf, &data, sizeof(data));
}

static int write_mark_updates(struct mail_index *index, buffer_t *marks,
			      const char *path, int fd)
{
	const uint32_t *data, *end;
	size_t size;

	data = buffer_get_data(marks, &size);
	end = data + size/sizeof(uint32_t);

	while (data < end) {
		if (pwrite(fd, data+1, sizeof(*data), data[0]) < 0) {
			index_file_set_syscall_error(index, path, "pwrite()");
			return FALSE;
		}
		data += 2;
	}
	return TRUE;
}

static void write_mark_updates_in_memory(buffer_t *marks, void *mmap_base,
					 size_t mmap_length)
{
	const unsigned char *data, *end;
	uint32_t offset;
	size_t size;

	data = buffer_get_data(marks, &size);
	end = data + size;

	while (data < end) {
		memcpy(&offset, data, sizeof(offset));
		data += sizeof(offset);

		i_assert(offset <= mmap_length - sizeof(uint32_t));
		memcpy((char *) mmap_base + offset, data, sizeof(uint32_t));
		data += sizeof(uint32_t);
	}
}

static void commit_all_changes_in_memory(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;

	if (ctx->cache_marks != NULL) {
		write_mark_updates_in_memory(ctx->cache_marks,
					     cache->mmap_base,
					     cache->mmap_length);
	}
	if (ctx->index_marks != NULL) {
		write_mark_updates_in_memory(ctx->index_marks,
					     cache->index->mmap_base,
					     cache->index->mmap_used_length);
	}
}

static int commit_all_changes(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	uint32_t cont;

	if (ctx->cache->anon_mmap) {
		commit_all_changes_in_memory(ctx);
		return TRUE;
	}

	/* write everything to disk */
	if (msync(cache->mmap_base, cache->mmap_length, MS_SYNC) < 0)
		return mail_cache_set_syscall_error(cache, "msync()");

	if (fdatasync(cache->fd) < 0)
		return mail_cache_set_syscall_error(cache, "fdatasync()");

	if (ctx->cache_marks != NULL &&
	    buffer_get_used_size(ctx->cache_marks) != 0) {
		/* now that we're sure it's there, set on all the used-bits */
		if (!write_mark_updates(cache->index, ctx->cache_marks,
					cache->filepath, cache->fd))
			return FALSE;

		/* update continued records count */
		cont = nbo_to_uint32(cache->header->continued_record_count);

		cont += buffer_get_used_size(ctx->cache_marks) /
			(sizeof(uint32_t) * 2);

		if (cont * 100 / cache->index->header->messages_count >=
		    COMPRESS_CONTINUED_PERCENTAGE &&
		    cache->used_file_size >= COMPRESS_MIN_SIZE) {
			/* too many continued rows, compress */
			cache->index->set_flags |=
				MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;
		}

		cache->header->continued_record_count = uint32_to_nbo(cont);
	}

	/* write index last */
	if (ctx->index_marks != NULL &&
	    buffer_get_used_size(ctx->index_marks) != 0) {
		if (!mail_index_fmdatasync(cache->index,
					   cache->index->mmap_used_length))
			return FALSE;

		if (!write_mark_updates(cache->index, ctx->index_marks,
					cache->index->filepath,
					cache->index->fd))
			return FALSE;
	}
	return TRUE;
}

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx)
{
	int ret = TRUE;

	if (ctx->last_idx != (unsigned int)-1) {
		if (!mail_cache_write(ctx))
			return FALSE;
	}

	ctx->cache->header->used_file_size =
		uint32_to_nbo(ctx->cache->used_file_size);

	if (!commit_all_changes(ctx))
		ret = FALSE;

	if (ctx->next_unused_header_lowwater == MAIL_CACHE_HEADERS_COUNT) {
		/* they're all used - compress the cache to get more */
		ctx->cache->index->set_flags |=
			MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;
	}

	mail_cache_transaction_flush(ctx);
	return ret;
}

int mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	unsigned int i;

	/* no need to actually modify the file - we just didn't update
	   used_file_size */
	cache->used_file_size = nbo_to_uint32(cache->header->used_file_size);

	/* make sure we don't cache the headers */
	for (i = 0; i < ctx->next_unused_header_lowwater; i++) {
		if (offset_to_uint32(cache->header->header_offsets[i]) == 0)
			cache->split_offsets[i] = 1;
	}

	mail_cache_transaction_flush(ctx);
	return TRUE;
}

static int mail_cache_grow(struct mail_cache *cache, uint32_t size)
{
	struct stat st;
	void *base;
	uoff_t grow_size, new_fsize;

	new_fsize = cache->used_file_size + size;
	grow_size = new_fsize / 100 * MAIL_CACHE_GROW_PERCENTAGE;
	if (grow_size < 16384)
		grow_size = 16384;

	new_fsize += grow_size;
	new_fsize &= ~1023;

	if (cache->anon_mmap) {
		i_assert(new_fsize < SSIZE_T_MAX);

		base = mremap_anon(cache->mmap_base, cache->mmap_length,
				   (size_t)new_fsize, MREMAP_MAYMOVE);
		if (base == MAP_FAILED) {
			mail_cache_set_syscall_error(cache, "mremap_anon()");
			return FALSE;
		}

		cache->mmap_base = base;
		cache->mmap_length = (size_t)new_fsize;
		cache->header = cache->mmap_base;
		return TRUE;
	}

	if (fstat(cache->fd, &st) < 0)
		return mail_cache_set_syscall_error(cache, "fstat()");

	if (cache->used_file_size + size <= (uoff_t)st.st_size) {
		/* no need to grow, just update mmap */
		if (!mmap_update(cache, 0, 0))
			return FALSE;

		i_assert(cache->mmap_length >= (uoff_t)st.st_size);
		return TRUE;
	}

	if (st.st_size < (off_t)sizeof(struct mail_cache_header))
		return mail_cache_set_corrupted(cache, "Header is missing");

	if (file_set_size(cache->fd, (off_t)new_fsize) < 0)
		return mail_cache_set_syscall_error(cache, "file_set_size()");

	return mmap_update(cache, 0, 0);
}

static uint32_t mail_cache_append_space(struct mail_cache_transaction_ctx *ctx,
					uint32_t size)
{
	/* NOTE: must be done within transaction or rollback would break it */
	uint32_t offset;

	i_assert((size & 3) == 0);

	offset = ctx->cache->used_file_size;
	if (offset >= 0x40000000) {
		index_set_error(ctx->cache->index, "Cache file too large: %s",
				ctx->cache->filepath);
		return 0;
	}

	if (offset + size > ctx->cache->mmap_length) {
		if (!mail_cache_grow(ctx->cache, size))
			return 0;
	}

	ctx->cache->used_file_size += size;
	return offset;
}

static const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx)
{
	uint32_t offset, data_size;
	unsigned char *buf;

	offset = offset_to_uint32(cache->header->header_offsets[idx]);

	if (offset == 0)
		return NULL;

	if (!mmap_update(cache, offset, 1024))
		return NULL;

	if (offset + sizeof(data_size) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	memcpy(&data_size, buf + offset, sizeof(data_size));
	data_size = nbo_to_uint32(data_size);
	offset += sizeof(data_size);

	if (data_size == 0) {
		mail_cache_set_corrupted(cache,
			"Header %u points to empty string", idx);
		return NULL;
	}

	if (!mmap_update(cache, offset, data_size))
		return NULL;

	if (offset + data_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	if (buf[offset + data_size - 1] != '\0') {
		mail_cache_set_corrupted(cache,
			"Header %u points to invalid string", idx);
		return NULL;
	}

	return buf + offset;
}

static const char *const *
split_header(struct mail_cache *cache, const char *header)
{
	const char *const *arr, *const *tmp;
	const char *null = NULL;
	char *str;
	buffer_t *buf;

	if (header == NULL)
		return NULL;

	arr = t_strsplit(header, "\n");
	buf = buffer_create_dynamic(cache->split_header_pool, 32, (size_t)-1);
	for (tmp = arr; *tmp != NULL; tmp++) {
		str = p_strdup(cache->split_header_pool, *tmp);
		buffer_append(buf, &str, sizeof(str));
	}
	buffer_append(buf, &null, sizeof(null));

	return buffer_get_data(buf, NULL);
}

const char *const *mail_cache_get_header_fields(struct mail_cache *cache,
						unsigned int idx)
{
	const char *str;
	int i;

	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);

	/* t_strsplit() is a bit slow, so we cache it */
	if (cache->header->header_offsets[idx] != cache->split_offsets[idx]) {
		p_clear(cache->split_header_pool);

		t_push();
		for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
			cache->split_offsets[i] =
				cache->header->header_offsets[i];

			str = mail_cache_get_header_fields_str(cache, i);
			cache->split_headers[i] = split_header(cache, str);
		}
		t_pop();
	}

	return cache->split_headers[idx];
}

static const char *write_header_string(const char *const headers[],
				       uint32_t *size_r)
{
	buffer_t *buffer;
	size_t size;

	buffer = buffer_create_dynamic(pool_datastack_create(),
				       512, (size_t)-1);

	while (*headers != NULL) {
		if (buffer_get_used_size(buffer) != 0)
			buffer_append(buffer, "\n", 1);
		buffer_append(buffer, *headers, strlen(*headers));
		headers++;
	}
	buffer_append(buffer, null4, 1);

	size = buffer_get_used_size(buffer);
	if ((size & 3) != 0) {
		buffer_append(buffer, null4, 4 - (size & 3));
		size += 4 - (size & 3);
	}
	*size_r = size;
	return buffer_get_data(buffer, NULL);
}

int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[])
{
	struct mail_cache *cache = ctx->cache;
	uint32_t offset, update_offset, size;
	const char *header_str, *prev_str;

	i_assert(*headers != NULL);
	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);
	i_assert(idx >= ctx->next_unused_header_lowwater);
	i_assert(offset_to_uint32(cache->header->header_offsets[idx]) == 0);

	t_push();

	header_str = write_header_string(headers, &size);
	if (idx != 0) {
		prev_str = mail_cache_get_header_fields_str(cache, idx-1);
		if (prev_str == NULL) {
			t_pop();
			return FALSE;
		}

		i_assert(strcmp(header_str, prev_str) != 0);
	}

	offset = mail_cache_append_space(ctx, size + sizeof(uint32_t));
	if (offset != 0) {
		memcpy((char *) cache->mmap_base + offset + sizeof(uint32_t),
		       header_str, size);

		size = uint32_to_nbo(size);
		memcpy((char *) cache->mmap_base + offset,
		       &size, sizeof(uint32_t));

		/* update cached headers */
		cache->split_offsets[idx] = cache->header->header_offsets[idx];
		cache->split_headers[idx] = split_header(cache, header_str);

		/* mark used-bit to be updated later. not really needed for
		   read-safety, but if transaction get rolled back we can't let
		   this point to invalid location. */
		update_offset = (char *) &cache->header->header_offsets[idx] -
			(char *) cache->mmap_base;
		mark_update(&ctx->cache_marks, update_offset,
			    uint32_to_offset(offset));

		/* make sure get_header_fields() still works for this header
		   while the transaction isn't yet committed. */
		ctx->next_unused_header_lowwater = idx + 1;
	}

	t_pop();
	return offset > 0;
}

static struct mail_cache_record *
cache_get_record(struct mail_cache *cache, uint32_t offset)
{
#define CACHE_PREFETCH 1024
	struct mail_cache_record *cache_rec;
	size_t size;

	offset = offset_to_uint32(offset);
	if (offset == 0)
		return NULL;

	if (!mmap_update(cache, offset, sizeof(*cache_rec) + CACHE_PREFETCH))
		return NULL;

	if (offset + sizeof(*cache_rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	cache_rec = CACHE_RECORD(cache, offset);

	size = nbo_to_uint32(cache_rec->size);
	if (size < sizeof(*cache_rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return NULL;
	}
	if (size > CACHE_PREFETCH) {
		if (!mmap_update(cache, offset, size))
			return NULL;
	}

	if (offset + size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	return cache_rec;
}

static struct mail_cache_record *
cache_get_next_record(struct mail_cache *cache, struct mail_cache_record *rec)
{
	struct mail_cache_record *next;

	next = cache_get_record(cache, rec->next_offset);
	if (next != NULL && next <= rec) {
		mail_cache_set_corrupted(cache, "next_offset points backwards");
		return NULL;
	}
	return next;
}

static int mail_cache_write(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_record *cache_rec, *next;
	struct mail_index_record *rec;
	uint32_t write_offset, update_offset;
	const void *buf;
	size_t size, buf_size;

	buf = buffer_get_data(ctx->cache_data, &buf_size);

	size = sizeof(*cache_rec) + buf_size;
	ctx->cache_rec.size = uint32_to_nbo(size);

	write_offset = mail_cache_append_space(ctx, size);
	if (write_offset == 0)
		return FALSE;

	rec = INDEX_RECORD_AT(ctx->cache->index, ctx->last_idx);
	ctx->last_idx = (unsigned int)-1;

	cache_rec = cache_get_record(cache, rec->cache_offset);
	if (cache_rec == NULL) {
		/* first cache record - update offset in index file */
		i_assert(cache->index->lock_type == MAIL_LOCK_EXCLUSIVE);

		/* mark cache_offset to be updated later */
		update_offset = (char *) &rec->cache_offset -
			(char *) cache->index->mmap_base;
		mark_update(&ctx->index_marks, update_offset,
			    uint32_to_offset(write_offset));
	} else {
		/* find the last cache record */
		while ((next = cache_get_next_record(cache, cache_rec)) != NULL)
			cache_rec = next;

		/* mark next_offset to be updated later */
		update_offset = (char *) &cache_rec->next_offset -
			(char *) cache->mmap_base;
		mark_update(&ctx->cache_marks, update_offset,
			    uint32_to_offset(write_offset));
	}

	memcpy((char *) cache->mmap_base + write_offset,
	       &ctx->cache_rec, sizeof(ctx->cache_rec));
	memcpy((char *) cache->mmap_base + write_offset +
	       sizeof(ctx->cache_rec), buf, buf_size);

	/* reset the write context */
	memset(&ctx->cache_rec, 0, sizeof(ctx->cache_rec));
	buffer_set_used_size(ctx->cache_data, 0);
	return TRUE;
}

static struct mail_cache_record *
mail_cache_lookup(struct mail_cache *cache, const struct mail_index_record *rec,
		  enum mail_cache_field fields)
{
	struct mail_cache_record *cache_rec;
	unsigned int idx;

	if (cache->trans_ctx != NULL &&
	    cache->trans_ctx->first_uid <= rec->uid &&
	    cache->trans_ctx->last_uid >= rec->uid &&
	    (cache->trans_ctx->prev_uid != rec->uid || fields == 0 ||
	     (cache->trans_ctx->prev_fields & fields) != 0)) {
		/* we have to auto-commit since we're not capable of looking
		   into uncommitted records. it would be possible by checking
		   index_marks and cache_marks, but it's just more trouble
		   than worth. */
		idx = INDEX_RECORD_INDEX(cache->index, rec);
		if (cache->trans_ctx->last_idx == idx) {
			if (!mail_cache_write(cache->trans_ctx))
				return NULL;
		}

		if (!mail_cache_transaction_commit(cache->trans_ctx))
			return NULL;
	}

	cache_rec = cache_get_record(cache, rec->cache_offset);
	if (cache_rec == NULL)
		return NULL;

	return cache_rec;
}

static int get_field_num(enum mail_cache_field field)
{
	unsigned int mask;
	int i;

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((field & mask) != 0)
			return i;
	}

	return -1;
}

static size_t get_insert_offset(struct mail_cache_transaction_ctx *ctx,
				enum mail_cache_field field)
{
	const unsigned char *buf;
	unsigned int mask;
	uint32_t data_size;
	size_t offset = 0;
	int i;

	buf = buffer_get_data(ctx->cache_data, NULL);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((field & mask) != 0)
			return offset;

		if ((ctx->cache_rec.fields & mask) != 0) {
			if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
				data_size = mail_cache_field_sizes[i];
			else {
				memcpy(&data_size, buf + offset,
				       sizeof(data_size));
				data_size = nbo_to_uint32(data_size);
				offset += sizeof(data_size);
			}
			offset += (data_size + 3) & ~3;
		}
	}

	i_unreached();
	return offset;
}

int mail_cache_add(struct mail_cache_transaction_ctx *ctx,
		   struct mail_index_record *rec, enum mail_cache_field field,
		   const void *data, size_t data_size)
{
	uint32_t nb_data_size;
	size_t full_size, offset;
	unsigned char *buf;
	unsigned int idx;
	int field_num;

	i_assert(data_size > 0);
	i_assert(data_size < (uint32_t)-1);

	nb_data_size = uint32_to_nbo((uint32_t)data_size);

	if ((field & MAIL_CACHE_FIXED_MASK) != 0) {
		field_num = get_field_num(field);
		i_assert(field_num != -1);
		i_assert(mail_cache_field_sizes[field_num] == data_size);
	} else if ((field & MAIL_CACHE_STRING_MASK) != 0) {
		i_assert(((char *) data)[data_size-1] == '\0');
	}

	/* NOTE: we use index because the record pointer might not last. */
        idx = INDEX_RECORD_INDEX(ctx->cache->index, rec);
	if (ctx->last_idx != idx && ctx->last_idx != (unsigned int)-1) {
		if (!mail_cache_write(ctx))
			return FALSE;
	}
	ctx->last_idx = idx;

	i_assert((ctx->cache_rec.fields & field) == 0);

	full_size = (data_size + 3) & ~3;
	if ((field & MAIL_CACHE_FIXED_MASK) == 0)
		full_size += sizeof(nb_data_size);

	/* fields must be ordered. find where to insert it. */
	if (field > ctx->cache_rec.fields)
                buf = buffer_append_space_unsafe(ctx->cache_data, full_size);
	else {
		offset = get_insert_offset(ctx, field);
		buffer_copy(ctx->cache_data, offset + full_size,
			    ctx->cache_data, offset, (size_t)-1);
		buf = buffer_get_space_unsafe(ctx->cache_data,
					      offset, full_size);
	}
	ctx->cache_rec.fields |= field;

	/* @UNSAFE */
	if ((field & MAIL_CACHE_FIXED_MASK) == 0) {
		memcpy(buf, &nb_data_size, sizeof(nb_data_size));
		buf += sizeof(nb_data_size);
	}
	memcpy(buf, data, data_size); buf += data_size;
	if ((data_size & 3) != 0)
		memset(buf, 0, 4 - (data_size & 3));

	/* remember the transaction uid range */
	if (rec->uid < ctx->first_uid || ctx->first_uid == 0)
		ctx->first_uid = rec->uid;
	if (rec->uid > ctx->last_uid)
		ctx->last_uid = rec->uid;

	if (ctx->prev_uid != rec->uid) {
		ctx->prev_uid = rec->uid;
		ctx->prev_fields = 0;
	}
	ctx->prev_fields |= field;

	return TRUE;
}

int mail_cache_delete(struct mail_cache_transaction_ctx *ctx,
		      struct mail_index_record *rec)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_record *cache_rec;
	uint32_t deleted_space;
	uoff_t max_del_space;

	cache_rec = mail_cache_lookup(cache, rec, 0);
	if (cache_rec == NULL)
		return TRUE;

	/* NOTE: it would be nice to erase the cached data for the record,
	   but some other processes might still be using them. So, we just
	   update the deleted_space in header */
	deleted_space = nbo_to_uint32(cache->header->deleted_space);

	do {
		deleted_space -= nbo_to_uint32(cache_rec->size);
		cache_rec = cache_get_next_record(cache, cache_rec);
	} while (cache_rec != NULL);

	/* see if we've reached the max. deleted space in file */
	max_del_space = cache->used_file_size / 100 * COMPRESS_PERCENTAGE;
	if (deleted_space >= max_del_space &&
	    cache->used_file_size >= COMPRESS_MIN_SIZE)
		cache->index->set_flags |= MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;

	cache->header->deleted_space = uint32_to_nbo(deleted_space);

	return TRUE;
}

enum mail_cache_field
mail_cache_get_fields(struct mail_cache *cache,
		      const struct mail_index_record *rec)
{
	struct mail_cache_record *cache_rec;
        enum mail_cache_field fields = 0;

	cache_rec = mail_cache_lookup(cache, rec, 0);
	while (cache_rec != NULL) {
		fields |= cache_rec->fields;
		cache_rec = cache_get_next_record(cache, cache_rec);
	}

	return fields;
}

static int cache_get_field(struct mail_cache *cache,
			   struct mail_cache_record *cache_rec,
			   enum mail_cache_field field,
			   void **data_r, size_t *size_r)
{
	unsigned char *buf;
	unsigned int mask;
	uint32_t rec_size, data_size;
	size_t offset, next_offset;
	int i;

	rec_size = nbo_to_uint32(cache_rec->size);
	buf = (unsigned char *) cache_rec;
	offset = sizeof(*cache_rec);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((cache_rec->fields & mask) == 0)
			continue;

		/* all records are at least 32bit. we have to check this
		   before getting data_size. */
		if (offset + sizeof(uint32_t) > rec_size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
			data_size = mail_cache_field_sizes[i];
		else {
			memcpy(&data_size, buf + offset, sizeof(data_size));
			data_size = nbo_to_uint32(data_size);
			offset += sizeof(data_size);
		}

		next_offset = offset + ((data_size + 3) & ~3);
		if (next_offset > rec_size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if (field == mask) {
			if (data_size == 0) {
				mail_cache_set_corrupted(cache,
							 "Field size is 0");
				return FALSE;
			}
			*data_r = buf + offset;
			*size_r = data_size;
			return TRUE;
		}
		offset = next_offset;
	}

	i_unreached();
	return FALSE;
}

static int cache_lookup_field(struct mail_cache *cache,
			      const struct mail_index_record *rec,
			      enum mail_cache_field field,
			      void **data_r, size_t *size_r)
{
	struct mail_cache_record *cache_rec;

	cache_rec = mail_cache_lookup(cache, rec, field);
	while (cache_rec != NULL) {
		if ((cache_rec->fields & field) != 0) {
			return cache_get_field(cache, cache_rec, field,
					       data_r, size_r);
		}
		cache_rec = cache_get_next_record(cache, cache_rec);
	}

	return FALSE;
}

int mail_cache_lookup_field(struct mail_cache *cache,
			    const struct mail_index_record *rec,
			    enum mail_cache_field field,
			    const void **data_r, size_t *size_r)
{
	void *data;

	if (!cache_lookup_field(cache, rec, field, &data, size_r))
		return FALSE;

	*data_r = data;
	return TRUE;
}

const char *mail_cache_lookup_string_field(struct mail_cache *cache,
					   const struct mail_index_record *rec,
					   enum mail_cache_field field)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_STRING_MASK) != 0);

	if (!mail_cache_lookup_field(cache, rec, field, &data, &size))
		return NULL;

	if (((const char *) data)[size-1] != '\0') {
		mail_cache_set_corrupted(cache,
			"String field %x doesn't end with NUL", field);
		return NULL;
	}
	return data;
}

int mail_cache_copy_fixed_field(struct mail_cache *cache,
				const struct mail_index_record *rec,
				enum mail_cache_field field,
				void *buffer, size_t buffer_size)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_FIXED_MASK) != 0);

	if (!mail_cache_lookup_field(cache, rec, field, &data, &size))
		return FALSE;

	if (buffer_size != size) {
		i_panic("cache: fixed field %x wrong size "
			"(%"PRIuSIZE_T" vs %"PRIuSIZE_T")",
			field, size, buffer_size);
	}

	memcpy(buffer, data, buffer_size);
	return TRUE;
}

void mail_cache_mark_missing(struct mail_cache *cache,
			     enum mail_cache_field fields)
{
	// FIXME: count these
}

enum mail_index_record_flag
mail_cache_get_index_flags(struct mail_cache *cache,
			   const struct mail_index_record *rec)
{
	enum mail_index_record_flag flags;

	if (!mail_cache_copy_fixed_field(cache, rec, MAIL_CACHE_INDEX_FLAGS,
					 &flags, sizeof(flags)))
		return 0;

	return flags;
}

int mail_cache_update_index_flags(struct mail_cache *cache,
				  struct mail_index_record *rec,
				  enum mail_index_record_flag flags)
{
	void *data;
	size_t size;

	i_assert(cache->locks > 0);

	if (!cache_lookup_field(cache, rec, MAIL_CACHE_INDEX_FLAGS,
				&data, &size)) {
		mail_cache_set_corrupted(cache,
			"Missing index flags for record %u", rec->uid);
		return FALSE;
	}

	memcpy(data, &flags, sizeof(flags));
	return TRUE;
}

int mail_cache_update_location_offset(struct mail_cache *cache,
				      struct mail_index_record *rec,
				      uoff_t offset)
{
	void *data;
	size_t size;

	i_assert(cache->locks > 0);

	if (!cache_lookup_field(cache, rec, MAIL_CACHE_LOCATION_OFFSET,
				&data, &size)) {
		mail_cache_set_corrupted(cache,
			"Missing location offset for record %u", rec->uid);
		return FALSE;
	}

	memcpy(data, &offset, sizeof(offset));
	return TRUE;
}

void *mail_cache_get_mmaped(struct mail_cache *cache, size_t *size)
{
	if (!mmap_update(cache, 0, 0))
		return NULL;

	*size = cache->mmap_length;
	return cache->mmap_base;
}

int mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
{
	va_list va;

	mail_cache_mark_file_deleted(cache);
	cache->index->inconsistent = TRUE; /* easiest way to rebuild */

	if (cache->silent)
		return FALSE;

	va_start(va, fmt);
	t_push();
	index_set_error(cache->index, "Corrupted index cache file %s: %s",
			cache->filepath, t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);

	return FALSE;
}
