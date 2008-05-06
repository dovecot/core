/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

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
#include "nfs-workarounds.h"
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

#define MAIL_HASH_SHRINK_PRESSURE 0.3
#define MAIL_HASH_GROW_PRESSURE 2

#define MAIL_HASH_TIMEOUT_SECS 60

struct mail_hash {
	struct mail_index *index;

	hash_callback_t *key_hash_cb;
	mail_hash_ctx_cmp_callback_t *key_compare_cb;
	mail_hash_remap_callback_t *remap_callback;
	hash_callback_t *rec_hash_cb;
	void *cb_context;
	unsigned int transaction_count;

	char *filepath;
	char *suffix;
	int fd;
	unsigned int record_size;

	dev_t dev;
	ino_t ino;

	void *mmap_base;
	size_t mmap_size;

	time_t mtime, mapped_mtime;
	size_t change_offset_start, change_offset_end;

	int lock_type;
	struct file_lock *file_lock;
	struct dotlock *dotlock;
	struct dotlock_settings dotlock_settings;

	const struct mail_hash_header *hdr;

	unsigned int in_memory:1;
	unsigned int recreate:1;
	unsigned int recreated:1;
};

#define HASH_RECORD_IDX(trans, idx) \
	PTR_OFFSET((trans)->records_base, (idx) * (trans)->hdr.record_size)

struct mail_hash_transaction {
	struct mail_hash *hash;

	struct mail_hash_header hdr;
	/* hash size is [hdr.hash_size] */
	uint32_t *hash_base;
	/* record [0] is always unused */
	void *records_base;
	/* number of records in records_base.
	   base_count + inserts.count == hdr.record_count */
	unsigned int base_count;

	/* bit array of modified data. each bit represents 1024 bytes of the
	   hash file. used only for data read into memory from hash (not
	   for mmaped data) */
	ARRAY_TYPE(uint32_t) updates;
	/* Records inserted within this transaction */
	ARRAY_TYPE(mail_hash_record) inserts;
	unsigned int next_grow_hashed_count;

	uint32_t *hash_buf;
	uint32_t records_base_1; /* used as records_base if base_count=1 */

	unsigned int failed:1;
	unsigned int mapped:1;
};

struct mail_hash_iterate_context {
	struct mail_hash_transaction *trans;
	uint32_t next_idx;
	unsigned int iter_count;
};

const struct dotlock_settings default_dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 10,
	MEMBER(stale_timeout) 30
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

void mail_hash_set_corrupted(struct mail_hash *hash, const char *error)
{
	mail_index_set_error(hash->index, "Corrupted index hash file %s: %s",
			     hash->filepath, error);
	if (unlink(hash->filepath) < 0 && errno != ENOENT)
		mail_hash_set_syscall_error(hash, "unlink()");
}

static inline struct mail_hash_record *
mail_hash_idx(struct mail_hash_transaction *trans, uint32_t idx)
{
	if (idx < trans->base_count)
		return HASH_RECORD_IDX(trans, idx);

	i_assert(idx < trans->hdr.record_count);
	return array_idx_modifiable(&trans->inserts, idx - trans->base_count);
}

static void mail_hash_file_close(struct mail_hash *hash)
{
	i_assert(hash->transaction_count == 0);

	if (hash->file_lock != NULL)
		file_lock_free(&hash->file_lock);

	if (hash->mmap_base != NULL) {
		if (munmap(hash->mmap_base, hash->mmap_size) < 0)
			mail_hash_set_syscall_error(hash, "munmap()");
		hash->mmap_base = NULL;
		hash->mmap_size = 0;
	}
	hash->ino = 0;
	hash->mapped_mtime = 0;

	if (hash->fd != -1) {
		if (close(hash->fd) < 0)
			mail_hash_set_syscall_error(hash, "close()");
		hash->fd = -1;
	}

	hash->hdr = NULL;
	hash->recreate = FALSE;
	hash->recreated = FALSE;
}

struct mail_hash *
mail_hash_alloc(struct mail_index *index, const char *suffix,
		unsigned int record_size,
		hash_callback_t *key_hash_cb,
		hash_callback_t *rec_hash_cb,
		mail_hash_ctx_cmp_callback_t *key_compare_cb,
		mail_hash_remap_callback_t *remap_callback,
		void *context)
{
	struct mail_hash *hash;

	i_assert(record_size >= sizeof(struct mail_hash_record));

	hash = i_new(struct mail_hash, 1);
	hash->index = index;
	hash->in_memory = MAIL_INDEX_IS_IN_MEMORY(index) || suffix == NULL;
	hash->filepath = hash->in_memory ? i_strdup("(in-memory hash)") :
		i_strconcat(index->filepath, suffix, NULL);
	hash->suffix = i_strdup(suffix);
	hash->record_size = record_size;
	hash->fd = -1;
	hash->lock_type = F_UNLCK;
	hash->dotlock_settings = default_dotlock_settings;
	hash->dotlock_settings.use_excl_lock = index->use_excl_dotlocks;
	hash->dotlock_settings.nfs_flush = index->nfs_flush;

	hash->key_hash_cb = key_hash_cb;
	hash->rec_hash_cb = rec_hash_cb;
	hash->key_compare_cb = key_compare_cb;
	hash->remap_callback = remap_callback,
	hash->cb_context = context;
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

static void
mail_hash_header_init(struct mail_hash *hash, unsigned int hash_size,
		      struct mail_hash_header *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->version = MAIL_HASH_VERSION;
	hdr->base_header_size = sizeof(*hdr);
	hdr->header_size = hdr->base_header_size;
	hdr->record_size = hash->record_size;
	/* note that since the index may not have been synced yet, the
	   uid_validity may be 0 */
	hdr->uid_validity = hash->index->map->hdr.uid_validity;

	hdr->hash_size = I_MAX(primes_closest(hash_size), MAIL_HASH_MIN_SIZE);
	hdr->record_count = 1; /* [0] always exists */
}

static bool mail_hash_check_header(struct mail_hash *hash,
				   const struct mail_hash_header *hdr)
{
	uoff_t file_size;

	if (hdr->version != MAIL_HASH_VERSION ||
	    (hdr->last_uid != 0 &&
	     hdr->uid_validity != hash->index->map->hdr.uid_validity) ||
	    (hdr->corrupted && hash->change_offset_end == 0)) {
		/* silent rebuild */
		if (unlink(hash->filepath) < 0 && errno != ENOENT)
			mail_hash_set_syscall_error(hash, "unlink()");
		return FALSE;
	}

	if (hdr->record_size != hash->record_size) {
		mail_hash_set_corrupted(hash, "record_size mismatch");
		return FALSE;
	}
	if (hdr->base_header_size != sizeof(*hdr)) {
		mail_hash_set_corrupted(hash, "base_header_size mismatch");
		return FALSE;
	}
	if (hdr->header_size < hdr->base_header_size) {
		mail_hash_set_corrupted(hash, "Invalid header_size");
		return FALSE;
	}
	if (hdr->record_count == 0) {
		mail_hash_set_corrupted(hash, "Invalid record_count");
		return FALSE;
	}
	if (hdr->hashed_count > hdr->record_count) {
		mail_hash_set_corrupted(hash, "Invalid hashed_count");
		return FALSE;
	}
	if (hdr->message_count > hdr->record_count - 1) {
		mail_hash_set_corrupted(hash, "Invalid message_count");
		return FALSE;
	}
	if (hdr->last_uid < hdr->message_count) {
		mail_hash_set_corrupted(hash, "Invalid last_uid");
		return FALSE;
	}
	if (hdr->uid_validity == 0 && hdr->message_count > 0) {
		mail_hash_set_corrupted(hash, "Zero uidvalidity");
		return FALSE;
	}

	if (hdr->hash_size < primes_closest(1)) {
		mail_hash_set_corrupted(hash, "Invalid hash_size");
		return FALSE;
	}

	file_size = hdr->header_size +
		hdr->hash_size * sizeof(uint32_t) +
		hdr->record_count * hdr->record_size;
	if (hash->mmap_size < file_size) {
		mail_hash_set_corrupted(hash, "File too small");
		return FALSE;
	}
	return TRUE;
}

static int mail_hash_file_fstat(struct mail_hash *hash, struct stat *st_r)
{
	if (fstat(hash->fd, st_r) < 0) {
		mail_hash_set_syscall_error(hash, "fstat()");
		return -1;
	}
	hash->dev = st_r->st_dev;
	hash->ino = st_r->st_ino;
	return 0;
}

static int mail_hash_file_map(struct mail_hash *hash, bool full)
{
	struct stat st;

	i_assert(hash->transaction_count == 0);
	i_assert(hash->lock_type != F_UNLCK);

	if (mail_hash_file_fstat(hash, &st) < 0)
		return -1;

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
				       MAP_PRIVATE, hash->fd, 0);
		if (hash->mmap_base == MAP_FAILED) {
			hash->mmap_size = 0;
			hash->mmap_base = NULL;
			mail_hash_set_syscall_error(hash, "mmap()");
			return -1;
		}
		hash->mapped_mtime = st.st_mtime;
	} else {
		//FIXME
	}
	hash->mtime = st.st_mtime;
	hash->hdr = hash->mmap_base;
	return 1;
}

static int mail_hash_file_map_header(struct mail_hash *hash)
{
	int ret;

	if (hash->fd == -1) {
		hash->hdr = NULL;
		return 1;
	}

	if ((ret = mail_hash_file_map(hash, FALSE)) <= 0)
		return ret;

	return mail_hash_check_header(hash, hash->hdr) ? 1 : 0;
}

static int mail_hash_open_fd(struct mail_hash *hash)
{
	hash->fd = nfs_safe_open(hash->filepath, O_RDWR);
	if (hash->fd == -1) {
		if (errno == ENOENT)
			return 0;
		mail_hash_set_syscall_error(hash, "open()");
		return -1;
	}
	return 1;
}

static int mail_hash_reopen_if_needed(struct mail_hash *hash)
{
	struct stat st;

	if (hash->fd == -1)
		return mail_hash_open_fd(hash);

	if (hash->index->nfs_flush)
		nfs_flush_file_handle_cache(hash->filepath);

	if (hash->ino == 0) {
		if (mail_hash_file_fstat(hash, &st) < 0)
			return -1;
	}

	if (nfs_safe_stat(hash->filepath, &st) < 0) {
		if (errno != ENOENT) {
			mail_hash_set_syscall_error(hash, "stat()");
			return -1;
		}
	} else if (st.st_ino == hash->ino && CMP_DEV_T(st.st_dev, hash->dev)) {
		/* the file looks the same */
		if (!hash->index->nfs_flush || fstat(hash->fd, &st) == 0) {
			/* it is the same */
			return 0;
		}
		if (errno != ESTALE) {
			mail_hash_set_syscall_error(hash, "fstat()");
			return -1;
		}
		/* ESTALE - another file renamed over */
	}
	mail_hash_file_close(hash);
	return mail_hash_open_fd(hash);
}

static int
mail_hash_file_lock(struct mail_hash *hash, int lock_type, bool try_lock)
{
	enum dotlock_create_flags flags;
	unsigned int timeout;
	int ret;

	i_assert(hash->fd != -1);

	if (hash->index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
		i_assert(hash->file_lock == NULL);

		timeout = !try_lock ? MAIL_HASH_TIMEOUT_SECS : 0;
		ret = file_wait_lock(hash->fd, hash->filepath, lock_type,
				     hash->index->lock_method,
				     timeout, &hash->file_lock);
		if (ret < 0 || (ret == 0 && !try_lock)) {
			mail_hash_set_syscall_error(hash,
						    "file_wait_lock()");
		}
	} else {
		i_assert(hash->dotlock == NULL);

		flags = try_lock ? DOTLOCK_CREATE_FLAG_NONBLOCK : 0;
		ret = file_dotlock_create(&hash->dotlock_settings,
					  hash->filepath, flags,
					  &hash->dotlock);
		if (ret < 0 || (ret == 0 && !try_lock)) {
			mail_hash_set_syscall_error(hash,
						    "file_dotlock_create()");
		}
	}
	return ret;
}

int mail_hash_lock_shared(struct mail_hash *hash)
{
	int ret;

	i_assert(hash->lock_type == F_UNLCK);

	if (hash->in_memory) {
		if (hash->hdr == NULL)
			return 0;
		hash->lock_type = F_RDLCK;
		return 1;
	}

	if (hash->fd == -1) {
		if ((ret = mail_hash_open_fd(hash)) <= 0)
			return ret;
	}

	do {
		if ((ret = mail_hash_file_lock(hash, F_RDLCK, FALSE)) <= 0)
			return -1;
	} while ((ret = mail_hash_reopen_if_needed(hash)) > 0);
	if (ret < 0 || hash->fd == -1)
		return ret;

	hash->lock_type = F_RDLCK;
	mail_index_flush_read_cache(hash->index, hash->filepath,
				    hash->fd, TRUE);
	if ((ret = mail_hash_file_map_header(hash)) <= 0) {
		mail_hash_unlock(hash);
		return ret;
	}
	return 1;
}

static int
mail_hash_lock_exclusive_fd(struct mail_hash *hash,
			    enum mail_hash_lock_flags flags)
{
	bool exists = TRUE;
	int ret;

	i_assert(hash->file_lock == NULL);
	i_assert(hash->dotlock == NULL);

	if (hash->index->lock_method == FILE_LOCK_METHOD_DOTLOCK) {
		/* use dotlocking */
	} else if (hash->fd == -1 && (ret = mail_hash_open_fd(hash)) <= 0) {
		if (ret < 0 ||
		    (flags & MAIL_HASH_LOCK_FLAG_CREATE_MISSING) == 0)
			return ret;
		/* the file doesn't exist - we need to use dotlocking */
		exists = FALSE;
	} else {
		/* first try to lock the file descriptor */
		ret = mail_hash_file_lock(hash, F_WRLCK, TRUE);
		if (ret != 0) {
			/* success / error */
			return ret;
		}
		if ((flags & MAIL_HASH_LOCK_FLAG_TRY) != 0)
			return 0;

		/* already locked. if it's only read-locked, we can
		   overwrite the file. first wait for a shared lock. */
		if (mail_hash_lock_shared(hash) <= 0)
			return -1;
		/* try once again if we can upgrade our shared lock to
		   an exclusive lock */
		ret = file_lock_try_update(hash->file_lock, F_WRLCK);
		if (ret != 0)
			return ret;
		/* still no luck - fallback to dotlocking */
	}
	if (file_dotlock_create(&hash->dotlock_settings, hash->filepath,
				0, &hash->dotlock) <= 0) {
		mail_hash_set_syscall_error(hash, "file_dotlock_create()");
		return -1;
	}
	if (!exists) {
		/* file didn't exist - see if someone just created it */
		i_assert(hash->fd == -1);
		ret = mail_hash_open_fd(hash);
		if (ret != 0) {
			(void)file_dotlock_delete(&hash->dotlock);
			if (ret < 0)
				return -1;

			/* the file was created - we need to have it locked,
			   so retry this operation */
			return mail_hash_lock_exclusive_fd(hash, flags);
		}
	}
	/* other sessions are reading the file, we must not overwrite */
	hash->recreate = TRUE;
	return 1;
}

int mail_hash_lock_exclusive(struct mail_hash *hash,
			     enum mail_hash_lock_flags flags)
{
	bool create_missing = (flags & MAIL_HASH_LOCK_FLAG_CREATE_MISSING) != 0;
	int ret;

	i_assert(hash->lock_type == F_UNLCK);

	if (hash->in_memory) {
		if (hash->hdr == NULL && !create_missing)
			return 0;
		hash->lock_type = F_WRLCK;
		return 1;
	}

	if ((ret = mail_hash_lock_exclusive_fd(hash, flags)) <= 0) {
		mail_hash_unlock(hash);
		return ret;
	}
	hash->lock_type = F_WRLCK;

	mail_index_flush_read_cache(hash->index, hash->filepath,
				    hash->fd, TRUE);
	if ((ret = mail_hash_file_map_header(hash)) <= 0) {
		mail_hash_unlock(hash);
		if (ret == 0 && create_missing) {
			/* the broken file was unlinked - try again */
			mail_hash_file_close(hash);
			return mail_hash_lock_exclusive(hash, flags);
		}
		return ret;
	}
	return 1;
}

void mail_hash_unlock(struct mail_hash *hash)
{
	if (hash->recreated)
		mail_hash_file_close(hash);

	if (hash->file_lock != NULL)
		file_unlock(&hash->file_lock);
	if (hash->dotlock != NULL)
		(void)file_dotlock_delete(&hash->dotlock);
	hash->lock_type = F_UNLCK;
}

static void mail_hash_resize(struct mail_hash_transaction *trans)
{
	struct mail_hash_record *rec;
	unsigned int idx, new_size, hash_idx, hash_key;

	new_size = I_MAX(primes_closest(trans->hdr.hashed_count),
			 MAIL_HASH_MIN_SIZE);
	i_assert(new_size != trans->hdr.hash_size);
	trans->hdr.hash_size = new_size;

	i_free(trans->hash_buf);
	trans->hash_buf = i_new(uint32_t, trans->hdr.hash_size);
	trans->hash_base = trans->hash_buf;

	for (idx = 1; idx < trans->hdr.record_count; idx++) {
		rec = mail_hash_idx(trans, idx);
		if (MAIL_HASH_RECORD_IS_DELETED(rec))
			continue;

		hash_key = trans->hash->rec_hash_cb(rec);
		if (hash_key == 0)
			continue;

		/* found a hashed record, move it to its new position */
		hash_idx = hash_key % trans->hdr.hash_size;
		rec->next_idx = trans->hash_buf[hash_idx];
		trans->hash_buf[hash_idx] = idx;
	}

	trans->next_grow_hashed_count =
		trans->hdr.hash_size * MAIL_HASH_GROW_PRESSURE;
	i_assert(trans->hdr.hashed_count < trans->next_grow_hashed_count);
}

struct mail_hash_transaction *
mail_hash_transaction_begin(struct mail_hash *hash, unsigned int min_hash_size)
{
	struct mail_hash_transaction *trans;

	i_assert(hash->lock_type != F_UNLCK);

	trans = i_new(struct mail_hash_transaction, 1);
	trans->hash = hash;
	if (hash->hdr != NULL)
		trans->hdr = *hash->hdr;
	else {
		mail_hash_header_init(hash, min_hash_size, &trans->hdr);
		trans->mapped = TRUE;
	}
	trans->base_count = trans->hdr.record_count;
	if (trans->base_count <= 1) {
		/* empty hash */
		trans->hash_buf = i_new(uint32_t, trans->hdr.hash_size);
		trans->hash_base = trans->hash_buf;
		trans->records_base = &trans->records_base_1;
	} else {
		trans->hash_base =
			PTR_OFFSET(hash->mmap_base, hash->hdr->header_size);
		trans->records_base = &trans->hash_base[hash->hdr->hash_size];
	}

	trans->next_grow_hashed_count =
		trans->hdr.hash_size * MAIL_HASH_GROW_PRESSURE;
	hash->transaction_count++;
	return trans;
}

int mail_hash_transaction_write(struct mail_hash_transaction *trans)
{
	struct mail_hash *hash = trans->hash;
	const struct mail_hash_record *inserts;
	unsigned int size, count, existing_size;
	const char *temp_path = NULL;
	uoff_t offset;
	float nodes_per_list;
	int fd = hash->fd;

	i_assert(hash->lock_type == F_WRLCK);

	if (trans->failed)
		return -1;
	if (!array_is_created(&trans->inserts) &&
	    !array_is_created(&trans->updates)) {
		/* nothing changed */
		return 0;
	}

	/* see if hash needs resizing */
	nodes_per_list = (float)trans->hdr.hashed_count /
		(float)trans->hdr.hash_size;
	if ((nodes_per_list < MAIL_HASH_SHRINK_PRESSURE &&
	     trans->hdr.hash_size > MAIL_HASH_MIN_SIZE) ||
	    nodes_per_list > MAIL_HASH_GROW_PRESSURE)
		mail_hash_resize(trans);

	if (trans->hash->in_memory)
		return 0;

	if (hash->recreate || hash->hdr->hash_size != trans->hdr.hash_size) {
		/* recreate the file instead of overwriting */
		fd = -1;
	}

	existing_size = sizeof(trans->hdr) +
		trans->hdr.hash_size * sizeof(uint32_t) +
		trans->base_count * trans->hdr.record_size;
	if (fd == -1) {
		temp_path = t_strconcat(hash->filepath, ".tmp", NULL);
		fd = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd == -1) {
			if (ENOSPACE(errno)) {
				hash->index->nodiskspace = TRUE;
				return -1;
			}
			mail_index_set_error(hash->index,
				"creat(%s) failed: %m", temp_path);
			return -1;
		}
	}

	if (pwrite_full(fd, &trans->hdr, sizeof(trans->hdr), 0) < 0) {
		mail_hash_set_syscall_error(hash, "pwrite()");
		return -1;
	}
	/* FIXME: use updates array */
	offset = sizeof(trans->hdr);
	if (pwrite_full(fd, trans->hash_base,
			trans->hdr.hash_size * sizeof(uint32_t), offset) < 0) {
		mail_hash_set_syscall_error(hash, "pwrite()");
		return -1;
	}
	offset += trans->hdr.hash_size * sizeof(uint32_t);
	/* if there's only the first null record, don't bother writing it.
	   especially because then records_base may point to sizeof(uint32_t)
	   instead of hdr.record_size */
	if (trans->base_count > 1) {
		if (pwrite_full(fd, trans->records_base,
				trans->base_count * trans->hdr.record_size,
				offset) < 0) {
			mail_hash_set_syscall_error(hash, "pwrite()");
			return -1;
		}
	}

	/* write the new data */
	if (array_is_created(&trans->inserts)) {
		inserts = array_get(&trans->inserts, &count);
		size = count * trans->hdr.record_size;
		if (pwrite_full(fd, inserts, size, existing_size) < 0) {
			mail_hash_set_syscall_error(hash, "pwrite()");
			return -1;
		}
	}
	if (temp_path != NULL) {
		if (rename(temp_path, hash->filepath) < 0) {
			mail_index_set_error(hash->index,
				"rename(%s, %s) failed: %m",
				temp_path, hash->filepath);
			return -1;
		}
		if (close(fd) < 0)
			mail_hash_set_syscall_error(hash, "close()");
		/* we must not overwrite before reopening the file */
		hash->recreate = TRUE;
		hash->recreated = TRUE;
	}
	return 0;
}

void mail_hash_transaction_end(struct mail_hash_transaction **_trans)
{
	struct mail_hash_transaction *trans = *_trans;

	*_trans = NULL;

	trans->hash->transaction_count--;
	if (array_is_created(&trans->inserts))
		array_free(&trans->inserts);
	if (array_is_created(&trans->updates))
		array_free(&trans->updates);
	i_free(trans->hash_buf);
	i_free(trans);
}

bool mail_hash_transaction_is_broken(struct mail_hash_transaction *trans)
{
	return trans->failed;
}

void mail_hash_transaction_set_corrupted(struct mail_hash_transaction *trans,
					 const char *error)
{
	trans->failed = TRUE;
	mail_hash_set_corrupted(trans->hash, error);
}

void mail_hash_reset(struct mail_hash_transaction *trans)
{
	mail_hash_header_init(trans->hash, trans->hdr.hash_size / 2,
			      &trans->hdr);
	trans->mapped = TRUE;
	trans->base_count = trans->hdr.record_count;
	i_assert(trans->base_count == 1);

	i_free(trans->hash_buf);
	trans->hash_buf = i_new(uint32_t, trans->hdr.hash_size);
	trans->hash_base = trans->hash_buf;
	trans->records_base = &trans->records_base_1;
}

int mail_hash_map_file(struct mail_hash_transaction *trans)
{
	if (!trans->mapped) {
		if (mail_hash_file_map(trans->hash, TRUE) <= 0) {
			trans->failed = TRUE;
			return -1;
		}
		trans->mapped = TRUE;
	}
	return 0;
}

struct mail_hash_header *
mail_hash_get_header(struct mail_hash_transaction *trans)
{
	return &trans->hdr;
}

static void mail_hash_iterate_init(struct mail_hash_iterate_context *iter,
				   struct mail_hash_transaction *trans,
				   uint32_t start_idx)
{
	memset(iter, 0, sizeof(*iter));
	iter->trans = trans;
	iter->next_idx = start_idx;
}

static int mail_hash_iterate_next(struct mail_hash_iterate_context *iter,
				  uint32_t *idx_r)
{
	struct mail_hash_record *rec;
	uint32_t idx = iter->next_idx;

	if (idx == 0)
		return 0;
	if (unlikely(idx >= iter->trans->hdr.record_count)) {
		mail_hash_transaction_set_corrupted(iter->trans,
			"Index points outside file");
		return -1;
	}
	rec = mail_hash_idx(iter->trans, idx);
	iter->next_idx = rec->next_idx;

	if (++iter->iter_count > iter->trans->hdr.record_count) {
		/* we've iterated through more indexes than there exist.
		   we must be looping. */
		mail_hash_transaction_set_corrupted(iter->trans,
			"next_iter loops");
		return -1;
	}
	*idx_r = idx;
	return 1;
}

void *mail_hash_lookup(struct mail_hash_transaction *trans, const void *key,
		       uint32_t *idx_r)
{
	struct mail_hash *hash = trans->hash;
	struct mail_hash_iterate_context iter;
	unsigned int hash_idx;
	uint32_t idx;
	int ret;

	hash_idx = hash->key_hash_cb(key) % trans->hdr.hash_size;
	mail_hash_iterate_init(&iter, trans, trans->hash_base[hash_idx]);

	while ((ret = mail_hash_iterate_next(&iter, &idx)) > 0) {
		if (hash->key_compare_cb(trans, key, idx, hash->cb_context))
			break;
	}

	if (ret <= 0) {
		*idx_r = 0;
		return NULL;
	} else {
		*idx_r = idx;
		return mail_hash_idx(trans, idx);
	}
}

void *mail_hash_lookup_idx(struct mail_hash_transaction *trans, uint32_t idx)
{
	i_assert(idx > 0);

	if (idx >= trans->hdr.record_count) {
		mail_hash_transaction_set_corrupted(trans,
			"Index points outside file");
		/* return pointer to the first dummy record */
		idx = 0;
	}

	return mail_hash_idx(trans, idx);
}

static uoff_t
mail_hash_idx_to_offset(struct mail_hash_transaction *trans, uint32_t idx)
{
	return trans->hdr.header_size +
		trans->hdr.hash_size * sizeof(uint32_t) +
		trans->hdr.record_size * idx;
}

static void
mail_hash_update_offset(struct mail_hash_transaction *trans,
			uoff_t offset, unsigned int size)
{
	uint32_t *p;
	unsigned int pos = offset / 1024;
	unsigned int pos2 = (offset + size - 1) / 1024;

	if (!array_is_created(&trans->updates))
		i_array_init(&trans->updates, I_MAX(pos, 256));

	while (pos <= pos2) {
		p = array_idx_modifiable(&trans->updates, pos / 32);
		*p |= 1 << (pos % 32);
		pos++;
	}
}

static void mail_hash_update_hash_idx(struct mail_hash_transaction *trans,
				      uint32_t hash_idx)
{
	size_t offset;

	offset = trans->hdr.header_size + hash_idx * sizeof(uint32_t);
	mail_hash_update_offset(trans, offset, sizeof(uint32_t));
}

static void mail_hash_insert_idx(struct mail_hash_transaction *trans,
				 const void *value, uint32_t *idx_r)
{
	struct mail_hash_record *rec;
	uint32_t idx;

	if (trans->hdr.first_hole_idx != 0) {
		/* allocate the record from the first hole */
		idx = trans->hdr.first_hole_idx;
		rec = mail_hash_idx(trans, idx);

		memcpy(&trans->hdr.first_hole_idx, rec + 1,
		       sizeof(trans->hdr.first_hole_idx));
		mail_hash_update(trans, idx);
	} else {
		idx = trans->hdr.record_count++;
		if (!array_is_created(&trans->inserts)) {
			array_create(&trans->inserts, default_pool,
				     trans->hdr.record_size, 128);
		}
		rec = array_append_space(&trans->inserts);
	}

	memcpy(rec, value, trans->hdr.record_size);
	rec->next_idx = 0;

	*idx_r = idx;
}

static void mail_hash_insert_hash(struct mail_hash_transaction *trans,
				  uint32_t hash_key, uint32_t idx)
{
	struct mail_hash_record *rec;
	uint32_t hash_idx;

	if (trans->hdr.hashed_count >= trans->next_grow_hashed_count)
		mail_hash_resize(trans);

	hash_idx = hash_key % trans->hdr.hash_size;

	rec = mail_hash_idx(trans, idx);
	rec->next_idx = trans->hash_base[hash_idx];
	trans->hash_base[hash_idx] = idx;

	mail_hash_update_hash_idx(trans, hash_idx);
	trans->hdr.hashed_count++;
}

void mail_hash_insert(struct mail_hash_transaction *trans, const void *key,
		      const void *value, uint32_t *idx_r)
{
	uint32_t hash_key;

	mail_hash_insert_idx(trans, value, idx_r);
	if (key == NULL)
		hash_key = 0;
	else {
		hash_key = trans->hash->key_hash_cb(key);
		mail_hash_insert_hash(trans, hash_key, *idx_r);
	}
	i_assert(trans->hash->rec_hash_cb(value) == hash_key);
}

void mail_hash_update(struct mail_hash_transaction *trans, uint32_t idx)
{
	uoff_t offset;

	i_assert(idx > 0 && idx < trans->hdr.record_count);

	offset = mail_hash_idx_to_offset(trans, idx);
	mail_hash_update_offset(trans, offset,
				trans->hdr.record_size);
}

static void
mail_hash_remove_idx(struct mail_hash_transaction *trans, uint32_t idx)
{
	struct mail_hash_record *rec;

	if (idx+1 == trans->hdr.record_count) {
		/* removing last record */
		trans->hdr.record_count--;
	} else {
		/* mark the record expunged */
		rec = mail_hash_idx(trans, idx);
		rec->next_idx = (uint32_t)-1;
		/* update the linked list of holes */
		i_assert(trans->hdr.record_size >=
			 sizeof(*rec) + sizeof(trans->hdr.first_hole_idx));
		memcpy(rec+1, &trans->hdr.first_hole_idx,
		       sizeof(trans->hdr.first_hole_idx));
		trans->hdr.first_hole_idx = idx;

		mail_hash_update(trans, idx);
	}
}

void mail_hash_remove(struct mail_hash_transaction *trans,
		      uint32_t idx, uint32_t key_hash)
{
	struct mail_hash_record *rec, *rec2;
	unsigned int hash_idx;
	uint32_t idx2;
	int ret;

	i_assert(idx > 0 && idx < trans->hdr.record_count);

	if (key_hash == 0) {
		/* key not in hash table */
		mail_hash_remove_idx(trans, idx);
		return;
	}

	rec = mail_hash_idx(trans, idx);

	hash_idx = key_hash % trans->hdr.hash_size;
	idx2 = trans->hash_base[hash_idx];
	if (idx2 == idx) {
		/* first in the hash table */
		trans->hash_base[hash_idx] = rec->next_idx;
		mail_hash_update_hash_idx(trans, hash_idx);
	} else {
		/* find the previous record */
		struct mail_hash_iterate_context iter;

		mail_hash_iterate_init(&iter, trans, idx2);
		while ((ret = mail_hash_iterate_next(&iter, &idx2)) > 0) {
			rec2 = mail_hash_idx(trans, idx2);
			if (rec2->next_idx == idx)
				break;
		}
		if (ret <= 0) {
			if (ret == 0) {
				mail_hash_set_corrupted(trans->hash,
					"Tried to remove non-existing key");
			}
			return;
		}

		rec2->next_idx = rec->next_idx;
		mail_hash_update_offset(trans, idx2, trans->hdr.record_size);

		if (trans->hdr.hashed_count == 0) {
			mail_hash_set_corrupted(trans->hash,
						"Too low hashed_count");
			return;
		}
		trans->hdr.hashed_count--;
	}

	mail_hash_remove_idx(trans, idx);
}
