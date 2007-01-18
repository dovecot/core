/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "primes.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
#include "file-set-size.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-hash.h"

#include <stdio.h>
#include <stddef.h>
#include <utime.h>
#include <sys/stat.h>

/* How large to create the file initially */
#define FILE_SIZE_INIT_PERCENTAGE 120
/* How much larger to grow the file when it needs to be done */
#define MAIL_HASH_GROW_PERCENTAGE 20
/* Minimum hash size to use */
#define MAIL_HASH_MIN_SIZE 109

#define MAIL_HASH_TIMEOUT_SECS 3

struct mail_hash {
	struct mail_index *index;

	hash_callback_t *key_hash_cb;
	hash_ctx_cmp_callback_t *key_compare_cb;
	hash_callback_t *rec_hash_cb;
	void *cb_context;

	char *filepath;
	char *suffix;
	int fd;

	dev_t dev;
	ino_t ino;

	unsigned int record_size;

	void *mmap_base;
	size_t mmap_size;

	time_t mtime, mapped_mtime;
	size_t change_offset_start, change_offset_end;

	int lock_type;
	struct file_lock *file_lock;
	struct dotlock *dotlock;
	struct dotlock_settings dotlock_settings;

	struct mail_hash_header *hdr;

	uint32_t *hash_base;
	void *records_base;
	unsigned int records_mapped;

	unsigned int mmap_anon:1;
	unsigned int in_memory:1;
	unsigned int locked:1;
};

#define MAIL_HASH_IS_IN_MEMORY(hash) \
	((hash)->in_memory)

#define HASH_RECORD_IDX(hash, idx) \
	PTR_OFFSET((hash)->records_base, ((idx) - 1) * (hash)->record_size)

const struct dotlock_settings default_dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 10,
	MEMBER(stale_timeout) 30,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

static void mail_hash_set_syscall_error(struct mail_hash *hash,
					const char *function)
{
	if (ENOSPACE(errno)) {
		hash->index->nodiskspace = TRUE;
		return;
	}

	mail_index_set_error(hash->index,
			     "%s failed with index hash file %s: %m",
			     function, hash->filepath);
}

static int mail_hash_file_set_corrupted(struct mail_hash *hash, bool set)
{
	size_t offset = offsetof(struct mail_hash_header, corrupted);
	struct stat st;

	if (hash->fd == -1)
		return 0;

	hash->hdr->corrupted = set ? 1 : 0;
	if (!hash->mmap_anon) {
		if (msync(hash->mmap_base,
			  offset + sizeof(hash->hdr->corrupted), MS_SYNC) < 0) {
			mail_hash_set_syscall_error(hash, "msync()");
			return -1;
		}
	} else {
		if (pwrite_full(hash->fd, &hash->hdr->corrupted,
				sizeof(hash->hdr->corrupted), offset) < 0) {
			mail_hash_set_syscall_error(hash, "pwrite_full()");
			return -1;
		}
	}
	if (fstat(hash->fd, &st) < 0 || st.st_mtime == hash->mtime) {
		/* mtime didn't change. have to increase it. */
		struct utimbuf buf;

		st.st_mtime++;
		buf.modtime = st.st_mtime;
		buf.actime = ioloop_time;
		if (utime(hash->filepath, &buf) < 0) {
			mail_hash_set_syscall_error(hash, "utime()");
			return -1;
		}
	}

	if (!set)
		hash->mapped_mtime = st.st_mtime;
	return 0;
}

void mail_hash_set_corrupted(struct mail_hash *hash, const char *error)
{
	mail_index_set_error(hash->index, "Corrupted index hash file %s: %s",
			     hash->filepath, error);

	(void)mail_hash_file_set_corrupted(hash, TRUE);
}

static int mail_hash_check_header(struct mail_hash *hash,
				  const struct mail_hash_header *hdr)
{
	uoff_t file_size;

	if (hdr->version != MAIL_HASH_VERSION ||
	    (hdr->last_uid != 0 &&
	     hdr->uid_validity != hash->index->hdr->uid_validity) ||
	    (hdr->corrupted && hash->change_offset_end == 0)) {
		/* silent rebuild */
		return -1;
	}

	if (hdr->record_size != hash->record_size) {
		mail_hash_set_corrupted(hash, "record_size mismatch");
		return -1;
	}
	if (hdr->base_header_size != sizeof(*hdr)) {
		mail_hash_set_corrupted(hash, "base_header_size mismatch");
		return -1;
	}
	if (hdr->header_size < hdr->base_header_size) {
		mail_hash_set_corrupted(hash, "Invalid header_size");
		return -1;
	}

	if (hdr->hash_size < primes_closest(1)) {
		mail_hash_set_corrupted(hash, "Invalid hash_size");
		return -1;
	}

	file_size = hdr->header_size +
		hdr->hash_size * sizeof(uint32_t) +
		hdr->record_size * hdr->record_count;
	if (hash->mmap_size < file_size) {
		mail_hash_set_corrupted(hash, "File too small");
		return -1;
	}

	return 0;
}

static void mail_hash_file_close(struct mail_hash *hash)
{
	if (hash->file_lock != NULL)
		file_lock_free(&hash->file_lock);

	if (hash->mmap_base != NULL) {
		if (hash->mmap_anon) {
			if (munmap_anon(hash->mmap_base, hash->mmap_size) < 0) {
				mail_hash_set_syscall_error(hash,
							    "munmap_anon()");
			}
		} else {
			if (munmap(hash->mmap_base, hash->mmap_size) < 0)
				mail_hash_set_syscall_error(hash, "munmap()");
		}
		hash->mapped_mtime = 0;
		hash->mmap_base = NULL;
		hash->mmap_size = 0;
		hash->mmap_anon = FALSE;
		hash->in_memory = FALSE;
	}

	if (hash->fd != -1) {
		if (close(hash->fd) < 0)
			mail_hash_set_syscall_error(hash, "close()");
		hash->fd = -1;
	}

	hash->hdr = NULL;
	hash->hash_base = NULL;
	hash->records_base = NULL;

	hash->locked = FALSE;
}

static int mail_hash_file_map_finish(struct mail_hash *hash)
{
	hash->hdr = hash->mmap_base;
	if (mail_hash_check_header(hash, hash->hdr) < 0) {
		i_assert(!MAIL_HASH_IS_IN_MEMORY(hash));
		mail_hash_file_close(hash);
		return 0;
	}

	hash->hash_base = PTR_OFFSET(hash->mmap_base, hash->hdr->header_size);
	hash->records_base = &hash->hash_base[hash->hdr->hash_size];
	hash->records_mapped =
		(hash->mmap_size -
		 ((char *)hash->records_base - (char *)hash->mmap_base)) /
		hash->record_size;
	return 1;
}

static int mail_hash_file_read(struct mail_hash *hash,
			       size_t file_size, size_t size)
{
	int ret;

	if (hash->mmap_base == NULL) {
		if (file_size < size)
			file_size = size;

		hash->mmap_base = mmap_anon(file_size);
		if (hash->mmap_base == MAP_FAILED) {
			hash->mmap_size = 0;
			hash->mmap_base = NULL;
			i_error("mmap_anon(%"PRIuSIZE_T") failed: %m",
				file_size);
			return -1;
		}
		hash->mmap_size = file_size;
		hash->mmap_anon = TRUE;
	} else if (size > hash->mmap_size) {
		i_assert(hash->mmap_anon);
		hash->mmap_base = mremap_anon(hash->mmap_base, hash->mmap_size,
					      size, MREMAP_MAYMOVE);
		if (hash->mmap_base == MAP_FAILED) {
			hash->mmap_size = 0;
			hash->mmap_base = NULL;
			mail_hash_set_syscall_error(hash, "mremap_anon()");
			return -1;
		}
		hash->mmap_size = size;
	}

	ret = pread_full(hash->fd, hash->mmap_base, size, 0);
	if (ret < 0) {
		mail_hash_set_syscall_error(hash, "pread_full()");
		return -1;
	}
	if (ret == 0) {
		mail_hash_set_corrupted(hash, "Unexpected end of file");
		return -1;
	}
	return 0;
}

static int mail_hash_file_write_changes(struct mail_hash *hash)
{
	if (hash->change_offset_end == 0) {
		/* no changes done */
		return 0;
	}

	if (!hash->mmap_anon) {
		if (msync(hash->mmap_base, hash->change_offset_end,
			  MS_SYNC) < 0) {
			mail_hash_set_syscall_error(hash, "msync()");
			return -1;
		}
	} else {
		if (pwrite_full(hash->fd, hash->mmap_base,
				sizeof(*hash->hdr), 0) < 0) {
			mail_hash_set_syscall_error(hash, "pwrite_full()");
			return -1;
		}
		if (pwrite_full(hash->fd, PTR_OFFSET(hash->mmap_base,
						     hash->change_offset_start),
				hash->change_offset_end -
				hash->change_offset_start,
				hash->change_offset_start) < 0) {
			mail_hash_set_syscall_error(hash, "pwrite_full()");
			return -1;
		}
	}

	if (!hash->index->fsync_disable) {
		if (fdatasync(hash->fd) < 0) {
			mail_hash_set_syscall_error(hash, "fdatasync()");
			return -1;
		}
	}

	/* now that the file is guaranteed to be updated, reset the
	   corruption marker */
	if (mail_hash_file_set_corrupted(hash, FALSE) < 0)
		return -1;

	hash->change_offset_start = hash->change_offset_end = 0;
	return 0;
}

static int mail_hash_mark_update(struct mail_hash *hash,
				 void *data, size_t size)
{
	size_t offset = (char *)data - (char *)hash->mmap_base;
	size_t end_offset = offset + size;

	i_assert(size > 0);

	if (hash->change_offset_end == 0) {
		/* first change. mark the file corrupted while changes are
		   being done. */
		if (mail_hash_file_set_corrupted(hash, TRUE) < 0)
			return -1;
	}

	if (offset < hash->change_offset_start)
		hash->change_offset_start = offset;
	if (end_offset > hash->change_offset_end)
		hash->change_offset_end = end_offset;
	return 0;
}

static int mail_hash_file_map(struct mail_hash *hash, bool full)
{
	struct stat st;
	size_t size;

	if (fstat(hash->fd, &st) < 0) {
		mail_hash_set_syscall_error(hash, "fstat()");
		return -1;
	}
	hash->dev = st.st_dev;
	hash->ino = st.st_ino;

	if (st.st_size < (off_t)sizeof(*hash->hdr)) {
		mail_hash_set_corrupted(hash, "File too small");
		return 0;
	}

	if (!hash->index->mmap_disable) {
		if (hash->mmap_base != NULL) {
			if (munmap(hash->mmap_base, hash->mmap_size) < 0)
				mail_hash_set_syscall_error(hash, "munmap()");
		}
		hash->mmap_size = st.st_size;
		hash->mmap_base = mmap(NULL, hash->mmap_size,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED, hash->fd, 0);
		if (hash->mmap_base == MAP_FAILED) {
			hash->mmap_size = 0;
			hash->mmap_base = NULL;
			mail_hash_set_syscall_error(hash, "mmap()");
			return -1;
		}
		hash->mapped_mtime = st.st_mtime;
	} else {
		/* first read only the header. if the update counter hasn't
		   changed we don't need to read the whole file */
		if (st.st_mtime != hash->mapped_mtime) {
			size = full ? st.st_size : (off_t)sizeof(*hash->hdr);
			if (mail_hash_file_read(hash, st.st_size, size) < 0)
				return -1;

			if (full)
				hash->mapped_mtime = st.st_mtime;
		} else {
			i_assert(hash->mmap_base != NULL);
		}
	}
	hash->mtime = st.st_mtime;

	return mail_hash_file_map_finish(hash);
}

static int mail_hash_file_lock(struct mail_hash *hash, int lock_type)
{
	i_assert(hash->fd != -1);

	if (hash->index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
		i_assert(hash->file_lock == NULL);
		return mail_index_lock_fd(hash->index, hash->filepath, hash->fd,
					  lock_type, MAIL_HASH_TIMEOUT_SECS,
					  &hash->file_lock);
	} else {
		i_assert(hash->dotlock == NULL);
		return file_dotlock_create(&hash->dotlock_settings,
					   hash->filepath, 0, &hash->dotlock);
	}
}

static void mail_hash_file_unlock(struct mail_hash *hash)
{
	i_assert(hash->fd != -1);

	if (hash->index->lock_method != FILE_LOCK_METHOD_DOTLOCK)
		file_unlock(&hash->file_lock);
	else
		(void)file_dotlock_delete(&hash->dotlock);
}

static int mail_hash_file_open(struct mail_hash *hash, bool lock)
{
	int ret;

	hash->fd = nfs_safe_open(hash->filepath, O_RDWR);
	if (hash->fd == -1) {
		if (errno == ENOENT)
			return 0;
		mail_hash_set_syscall_error(hash, "open()");
		return -1;
	}

	if (!lock) {
		if (mail_hash_file_lock(hash, F_RDLCK) <= 0)
			return -1;

		ret = mail_hash_file_map(hash, FALSE);
		if (hash->fd != -1)
			mail_hash_file_unlock(hash);
	} else {
		if (mail_hash_file_lock(hash, F_WRLCK) <= 0)
			return -1;

		hash->locked = TRUE;
		ret = mail_hash_file_map(hash, TRUE);

		if (ret <= 0)
			mail_hash_file_unlock(hash);
	}
	return ret;
}

static void
mail_hash_header_init(struct mail_hash *hash, unsigned int initial_count,
		      struct mail_hash_header *hdr, uoff_t *file_size_r)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->version = MAIL_HASH_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = hdr->base_header_size;
	hdr->record_size = hash->record_size;
	/* note that since the index may not have been synced yet, the
	   uid_validity may be 0 */
	hdr->uid_validity = hash->index->hdr->uid_validity;

	if (initial_count == 0)
		initial_count = I_MAX(hash->index->hdr->messages_count, 25);
	hdr->hash_size = I_MAX(primes_closest(initial_count * 2),
			       MAIL_HASH_MIN_SIZE);

	*file_size_r = hdr->header_size +
		hdr->hash_size * sizeof(uint32_t) +
		hash->record_size * (initial_count *
				     FILE_SIZE_INIT_PERCENTAGE / 100);
}

static int
mail_hash_file_create(struct mail_hash *hash, unsigned int initial_count)
{
	struct dotlock *dotlock;
	struct mail_hash_header hdr;
	uoff_t file_size;
	int fd;

	fd = file_dotlock_open(&hash->dotlock_settings,
			       hash->filepath, 0, &dotlock);
	if (fd == -1) {
		mail_hash_set_syscall_error(hash, "file_dotlock_open()");
		return -1;
	}

	mail_hash_header_init(hash, initial_count, &hdr, &file_size);
	if (write_full(fd, &hdr, sizeof(hdr)) < 0 ||
	    file_set_size(fd, file_size) < 0) {
		mail_hash_set_syscall_error(hash, "write()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	if (file_dotlock_replace(&dotlock, 0) < 0) {
		mail_hash_set_syscall_error(hash, "file_dotlock_replace()");
		return -1;
	}
	return 0;
}

static void mail_hash_create_in_memory(struct mail_hash *hash,
				       unsigned int initial_count)
{
	struct mail_hash_header hdr;
	uoff_t file_size;

	mail_hash_header_init(hash, initial_count, &hdr, &file_size);

	hash->mmap_size = file_size;
	hash->mmap_base = mmap_anon(hash->mmap_size);
	if (hash->mmap_base == MAP_FAILED)
		i_fatal("mmap_anon(%"PRIuSIZE_T") failed: %m", hash->mmap_size);
	hash->mmap_anon = TRUE;
	hash->in_memory = TRUE;

	i_assert(hash->mmap_size > sizeof(hdr));
	memcpy(hash->mmap_base, &hdr, sizeof(hdr));

	if (mail_hash_file_map_finish(hash) <= 0)
		i_unreached();
}

#undef mail_hash_open
struct mail_hash *
mail_hash_open(struct mail_index *index, const char *suffix,
	       enum mail_hash_open_flags flags, unsigned int record_size,
	       unsigned int initial_count,
	       hash_callback_t *key_hash_cb,
	       hash_callback_t *rec_hash_cb,
	       hash_ctx_cmp_callback_t *key_compare_cb,
	       void *context)
{
	struct mail_hash *hash;
	int ret;

	i_assert(record_size >= sizeof(struct mail_hash_record));

	hash = i_new(struct mail_hash, 1);
	hash->index = index;
	hash->filepath = (flags & MAIL_HASH_OPEN_FLAG_IN_MEMORY) != 0 ?
		i_strdup("(in-memory hash)") :
		i_strconcat(index->filepath, suffix, NULL);
	hash->suffix = i_strdup(suffix);
	hash->record_size = record_size;
	hash->fd = -1;
	hash->dotlock_settings = default_dotlock_settings;
	hash->dotlock_settings.use_excl_lock = index->use_excl_dotlocks;

	hash->key_hash_cb = key_hash_cb;
	hash->rec_hash_cb = rec_hash_cb;
	hash->key_compare_cb = key_compare_cb;
	hash->cb_context = context;

	ret = MAIL_INDEX_IS_IN_MEMORY(hash->index) ||
		(flags & MAIL_HASH_OPEN_FLAG_IN_MEMORY) != 0 ? -1 :
		mail_hash_file_open(hash, FALSE);

	if (ret <= 0 && (flags & MAIL_HASH_OPEN_FLAG_CREATE) == 0) {
		/* we don't want to create the hash */
		mail_hash_free(&hash);
		return NULL;
	}
	if (ret == 0) {
		/* not found or broken, recreate it */
		ret = mail_hash_reset(hash, initial_count);
	}
	if (ret < 0) {
		/* fallback to in-memory hash */
		mail_hash_file_close(hash);
		mail_hash_create_in_memory(hash, initial_count);
	}
	return hash;
}

void mail_hash_free(struct mail_hash **_hash)
{
	struct mail_hash *hash = *_hash;

	*_hash = NULL;

	mail_hash_file_close(hash);
	i_free(hash->filepath);
	i_free(hash->suffix);
	i_free(hash);
}

int mail_hash_reset(struct mail_hash *hash, unsigned int initial_count)
{
	bool locked = hash->locked;
	int ret;

	mail_hash_file_close(hash);

	ret = mail_hash_file_create(hash, initial_count);
	if (ret == 0) {
		/* should work now, try opening again */
		ret = mail_hash_file_open(hash, locked);
		if (ret == 0) {
			mail_hash_set_corrupted(hash,
				"Newly created hash file broken");
			return -1;
		}
	}
	return ret < 0 ? -1 : 0;
}

static int mail_hash_reopen(struct mail_hash *hash)
{
	int ret;

	mail_hash_file_close(hash);

	if ((ret = mail_hash_file_open(hash, FALSE)) < 0)
		return -1;
	if (ret > 0)
		return 0;

	/* not found or broken, recreate it */
	return mail_hash_reset(hash, 0);
}

static int mail_hash_reopen_if_needed(struct mail_hash *hash)
{
	struct stat st;

	if (hash->fd == -1)
		return mail_hash_reopen(hash);

	if (stat(hash->filepath, &st) < 0) {
		if (errno == ENOENT)
			return mail_hash_reopen(hash);

		if (errno != ESTALE) {
			mail_hash_set_syscall_error(hash, "stat()");
			return -1;
		}
		/* if ESTALE is returned, it most likely means it was rebuilt */
	} else {
		if (st.st_ino == hash->ino && CMP_DEV_T(st.st_dev, hash->dev))
			return 0;
	}
	return mail_hash_reopen(hash);
}

int mail_hash_lock(struct mail_hash *hash)
{
	int ret;

	i_assert(!hash->locked);
	if (!MAIL_HASH_IS_IN_MEMORY(hash)) {
		if (mail_hash_reopen_if_needed(hash) < 0)
			return -1;
		if ((ret = mail_hash_file_lock(hash, F_WRLCK)) <= 0)
			return ret;

		if (mail_hash_file_map(hash, TRUE) <= 0) {
			mail_hash_file_unlock(hash);
			return -1;
		}
	}
	if (hash->hdr->uid_validity == 0) {
		i_assert(hash->hdr->last_uid == 0);
		hash->hdr->uid_validity = hash->index->hdr->uid_validity;
	}
	hash->locked = TRUE;
	return 1;
}

void mail_hash_unlock(struct mail_hash *hash)
{
	i_assert(hash->locked);

	hash->locked = FALSE;
	if (MAIL_HASH_IS_IN_MEMORY(hash))
		return;

	if (hash->fd != -1) {
		(void)mail_hash_file_write_changes(hash);
		mail_hash_file_unlock(hash);
	}
}

const struct mail_hash_header *mail_hash_get_header(struct mail_hash *hash)
{
	return hash->hdr;
}

int mail_hash_lookup(struct mail_hash *hash, const void *key,
		     const void **value_r, uint32_t *idx_r)
{
	const struct mail_hash_record *rec;
	unsigned int hash_idx;
	uint32_t idx;

	hash_idx = hash->key_hash_cb(key) % hash->hdr->hash_size;
	for (idx = hash->hash_base[hash_idx]; idx != 0; ) {
		if (idx > hash->hdr->record_count) {
			mail_hash_set_corrupted(hash,
				"Index points outside file");
			return -1;
		}

		rec = HASH_RECORD_IDX(hash, idx);
		if (hash->key_compare_cb(key, rec, hash->cb_context)) {
			*idx_r = idx;
			*value_r = rec;
			return 1;
		}

		if (idx == rec->next_idx) {
			mail_hash_set_corrupted(hash, "next_idx loops");
			return -1;
		}
		idx = rec->next_idx;
	}
	return 0;
}

static int mail_hash_update_header(struct mail_hash *hash,
				   struct mail_hash_record *rec, bool had_uid)
{
	if (rec->uid != 0) {
		if (!had_uid) {
			hash->hdr->message_count++;
			if (hash->hdr->message_count >
			    hash->hdr->record_count) {
				mail_hash_set_corrupted(hash,
					"Too high message_count");
				return -1;
			}
		}
		if (rec->uid > hash->hdr->last_uid)
			hash->hdr->last_uid = rec->uid;
	} else {
		if (had_uid) {
			if (hash->hdr->message_count == 0) {
				mail_hash_set_corrupted(hash,
					"Too low message_count");
				return -1;
			}
			hash->hdr->message_count--;
		}
	}
	return 0;
}

static int mail_hash_grow_file(struct mail_hash *hash)
{
	unsigned int message_count;
	size_t new_size, grow_size;

	grow_size = hash->mmap_size * 100 / MAIL_HASH_GROW_PERCENTAGE;
	message_count = hash->index->hdr->messages_count;
	if (hash->hdr->record_count < message_count) {
		/* if lots of messages have been added, the grow percentage
		   may not be enough. */
		if (grow_size < message_count * hash->record_size)
			grow_size = message_count * hash->record_size;
	}
	new_size = hash->mmap_size + grow_size;

	if (!MAIL_HASH_IS_IN_MEMORY(hash)) {
		if (file_set_size(hash->fd, new_size) < 0) {
			mail_hash_set_syscall_error(hash, "file_set_size()");
			return -1;
		}
	}

	if (MAIL_HASH_IS_IN_MEMORY(hash)) {
		i_assert(hash->mmap_anon);
		hash->mmap_base = mremap_anon(hash->mmap_base, hash->mmap_size,
					      new_size, MREMAP_MAYMOVE);
		if (hash->mmap_base == MAP_FAILED) {
			hash->mmap_base = NULL;
			hash->mmap_size = 0;
			mail_hash_set_syscall_error(hash, "mremap_anon()");
			return -1;
		}
		hash->mmap_size = new_size;

		if (mail_hash_file_map_finish(hash) <= 0)
			return -1;
	} else {
		/* write the existing changes to the file and re-mmap it */
		if (msync(hash->mmap_base, hash->change_offset_end,
			  MS_SYNC) < 0) {
			mail_hash_set_syscall_error(hash, "msync()");
			return -1;
		}
		/* reset the change offsets since we've updated the file, but
		   since the corrupted-flag is still set don't set
		   change_offset_end=0 */
		hash->change_offset_start = 0;
		hash->change_offset_end = 1;

		if (mail_hash_file_map(hash, TRUE) <= 0)
			return -1;
	}
	return 0;
}

static int mail_hash_insert_with_hash(struct mail_hash *hash, const void *value,
				      uint32_t hash_key, uint32_t *idx_r)
{
	struct mail_hash_record *rec;
	uint32_t idx, *idx_p;

	if (hash->hdr->first_hole_idx != 0) {
		/* allocate the record from the first hole */
		idx = hash->hdr->first_hole_idx;
		rec = HASH_RECORD_IDX(hash, idx);

		if (mail_hash_mark_update(hash, rec, sizeof(*rec)) < 0)
			return -1;

		hash->hdr->first_hole_idx = rec->next_idx;
	} else {
		if (hash->hdr->record_count >= hash->records_mapped) {
			if (mail_hash_grow_file(hash) < 0)
				return -1;

			i_assert(hash->hdr->record_count <
				 hash->records_mapped);
		}

		idx = hash->hdr->record_count + 1;
		rec = HASH_RECORD_IDX(hash, idx);

		if (mail_hash_mark_update(hash, rec, sizeof(*rec)) < 0)
			return -1;

		hash->hdr->record_count++;
	}

	memcpy(rec, value, hash->record_size);
	rec->next_idx = 0;

	if (mail_hash_update_header(hash, rec, FALSE) < 0)
		return -1;

	if (hash_key != 0) {
		idx_p = &hash->hash_base[hash_key % hash->hdr->hash_size];
		while (*idx_p != 0) {
			rec = HASH_RECORD_IDX(hash, *idx_p);
			if (*idx_p == rec->next_idx) {
				mail_hash_set_corrupted(hash, "next_idx loops");
				return -1;
			}
			idx_p = &rec->next_idx;
		}

		if (mail_hash_mark_update(hash, idx_p, sizeof(*idx_p)) < 0)
			return -1;
		*idx_p = idx;

		hash->hdr->hashed_count++;
	}

	*idx_r = idx;
	return 0;
}

int mail_hash_insert(struct mail_hash *hash, const void *key,
		     const void *value, uint32_t *idx_r)
{
	uint32_t hash_key = key == NULL ? 0 : hash->key_hash_cb(key);

	i_assert((key == NULL && hash->rec_hash_cb(value) == 0) ||
		 (key != NULL && hash_key != 0 &&
		  hash->rec_hash_cb(value) != 0));

	return mail_hash_insert_with_hash(hash, value, hash_key, idx_r);
}

int mail_hash_remove(struct mail_hash *hash, const void *key)
{
	return mail_hash_remove_idx(hash, 0, key);
}

int mail_hash_remove_idx(struct mail_hash *hash, uint32_t idx, const void *key)
{
	struct mail_hash_record *rec = NULL;
	unsigned int hash_idx;
	uint32_t hash_key, *idx_p;

	i_assert(idx != 0 || key != NULL);

	if (key != NULL) {
		hash_idx = hash->key_hash_cb(key) % hash->hdr->hash_size;
		for (idx_p = &hash->hash_base[hash_idx]; *idx_p != 0; ) {
			if (*idx_p > hash->hdr->record_count) {
				mail_hash_set_corrupted(hash,
					"Index points outside file");
				return -1;
			}

			rec = HASH_RECORD_IDX(hash, *idx_p);
			if (idx != 0) {
				if (*idx_p == idx)
					break;
			} else {
				if (hash->key_compare_cb(key, rec,
							 hash->cb_context))
					break;
			}
			idx_p = &rec->next_idx;
		}

		idx = *idx_p;
		if (idx == 0) {
			mail_hash_set_corrupted(hash,
				"Tried to remove non-existing key");
			return -1;
		}

		if (mail_hash_mark_update(hash, idx_p, sizeof(*idx_p)) < 0)
			return -1;
		*idx_p = rec->next_idx;
	}

	if (rec->uid != 0) {
		if (hash->hdr->message_count == 0) {
			mail_hash_set_corrupted(hash, "Too low message_count");
			return -1;
		}
		hash->hdr->message_count--;
	}

	hash_key = hash->rec_hash_cb(rec);
	if (hash_key != 0) {
		if (hash->hdr->hashed_count == 0) {
			mail_hash_set_corrupted(hash, "Too low hashed_count");
			return -1;
		}
		hash->hdr->hashed_count--;
	}

	if (idx == hash->hdr->record_count) {
		hash->hdr->record_count--;
	} else {
		if (mail_hash_mark_update(hash, rec, sizeof(rec)) < 0)
			return -1;

		rec->uid = (uint32_t)-1;
		rec->next_idx = hash->hdr->first_hole_idx;
		hash->hdr->first_hole_idx = idx;
	}
	return 0;
}

unsigned int mail_hash_value_idx(struct mail_hash *hash, const void *value)
{
	const char *cvalue = value;
	const char *cbase = hash->records_base;
	unsigned int idx;

	i_assert(cvalue >= cbase);

	idx = (cvalue - cbase) / hash->record_size + 1;
	i_assert(idx <= hash->hdr->record_count);
	return idx;
}

int mail_hash_lookup_idx(struct mail_hash *hash, uint32_t idx,
			 const void **value_r)
{
	struct mail_hash_record *rec;

	i_assert(idx > 0);

	if (idx > hash->hdr->record_count) {
		mail_hash_set_corrupted(hash, "Index points outside file");
		return -1;
	}

	rec = HASH_RECORD_IDX(hash, idx);
	*value_r = rec;
	return 0;
}

int mail_hash_update_idx(struct mail_hash *hash, uint32_t idx,
			 const void *value)
{
	struct mail_hash_record *rec;
	bool had_uid;

	i_assert(idx > 0);

	if (idx > hash->hdr->record_count) {
		mail_hash_set_corrupted(hash, "Index points outside file");
		return -1;
	}

	rec = HASH_RECORD_IDX(hash, idx);
	if (mail_hash_mark_update(hash, rec, sizeof(*rec)) < 0)
		return -1;

	had_uid = rec->uid != 0;
	memcpy(rec, value, hash->record_size);

	return mail_hash_update_header(hash, rec, had_uid);
}

int mail_hash_resize_if_needed(struct mail_hash *hash, unsigned int grow_count,
			       mail_hash_resize_callback_t *callback,
			       void *context)
{
	struct mail_hash *tmp_hash;
	const struct mail_hash_record *rec;
	const char *tmp_filename;
	uint32_t hash_key, idx, new_idx, first_changed_idx, *map;
	float nodes_per_list;
	unsigned int map_size;
	int ret = 0;

	if (MAIL_HASH_IS_IN_MEMORY(hash))
		return 0;

	i_assert(hash->locked);

	nodes_per_list = (float)(hash->hdr->hashed_count + grow_count) /
		(float)hash->hdr->hash_size;
	if ((nodes_per_list > 0.3 && nodes_per_list < 2.0) ||
	    hash->hdr->hash_size <= MAIL_HASH_MIN_SIZE)
		return 0;

	/* create a temporary hash */
	tmp_hash = mail_hash_open(hash->index,
				  t_strconcat(hash->suffix, ".tmp", NULL),
				  MAIL_HASH_OPEN_FLAG_CREATE,
				  hash->record_size,
				  hash->hdr->hashed_count + grow_count,
				  hash->key_hash_cb,
				  hash->rec_hash_cb,
				  hash->key_compare_cb,
				  hash->cb_context);
	if (tmp_hash == NULL)
		return -1;

	/* populate */
	first_changed_idx = 0;
	map_size = hash->hdr->record_count + 1;
	map = i_new(uint32_t, map_size);
	for (idx = 1; idx <= hash->hdr->record_count; idx++) {
		rec = HASH_RECORD_IDX(hash, idx);
		hash_key = hash->rec_hash_cb(rec);

		if (MAIL_HASH_RECORD_IS_DELETED(rec))
			continue;

		if (mail_hash_insert_with_hash(tmp_hash, rec, hash_key,
					       &new_idx) < 0) {
			ret = -1;
			break;
		}

		if (first_changed_idx == 0 && idx != new_idx)
			first_changed_idx = idx;

		/* @UNSAFE: keep old -> new idx mapping */
		map[idx] = new_idx;
	}
	if (ret == 0 && first_changed_idx != 0) {
		if (callback(tmp_hash, first_changed_idx,
			     map, map_size, context) < 0)
			ret = -1;
	}
	i_free(map);
	(void)mail_hash_file_write_changes(tmp_hash);

	tmp_filename = t_strdup(tmp_hash->filepath);
	mail_hash_free(&tmp_hash);
	if (ret < 0) {
		(void)unlink(tmp_filename);
		return -1;
	}

	/* replace the old */
	if (rename(tmp_filename, hash->filepath) < 0) {
		mail_hash_set_syscall_error(hash, "rename()");
		(void)unlink(tmp_filename);
		return -1;
	}

	/* reopen the hash */
	mail_hash_file_close(hash);
	if ((ret = mail_hash_file_open(hash, TRUE)) < 0)
		return -1;
	if (ret == 0) {
		mail_hash_set_corrupted(hash,
			"Newly created hash file broken");
		return -1;
	}

	return 0;
}
