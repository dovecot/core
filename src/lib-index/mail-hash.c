/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-set-size.h"
#include "primes.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-hash.h"

#include <stdio.h>
#include <fcntl.h>

/* Minimum record count for a hash file. By default, the hash file size is
   the number of messages * 3, and it's rebuilt after the file is 3/4 full.
   Use only primes as hash file sizes. */
#define MIN_HASH_SIZE 109

/* Maximum record count for a hash file. */
#define MAX_HASH_SIZE \
	((INT_MAX - sizeof(MailHashHeader)) / 100)

/* When rebuilding hash, make it 30% full */
#define MIN_PERCENTAGE 30

/* Try rebuilding hash sometimes soon after it's 60% full */
#define REBUILD_PERCENTAGE 60

/* Force a rebuild when hash is 80% full */
#define FORCED_REBUILD_PERCENTAGE 80

/* our hashing function is simple - UID*2. The *2 is there because UIDs are
   normally contiguous, so once the UIDs wrap around, we don't want to go
   through lots of records just to find an empty spot */
#define HASH_FUNC(uid) (uid * 2)

#define HASH_FILE_SIZE(records) \
	(sizeof(MailHashHeader) + (records) * sizeof(MailHashRecord))

struct _MailHash {
	MailIndex *index;

	unsigned int size;

	int fd;
	char *filepath;

	void *mmap_base;
	size_t mmap_length;

	MailHashHeader *header;
	unsigned int anon_mmap:1;
	unsigned int dirty_mmap:1;
	unsigned int modified:1;
};

static int hash_set_syscall_error(MailHash *hash, const char *function)
{
	i_assert(function != NULL);

	index_set_error(hash->index, "%s failed with hash file %s: %m",
			function, hash->filepath);
	return FALSE;
}

static void mail_hash_file_close(MailHash *hash)
{
	if (close(hash->fd) < 0)
		hash_set_syscall_error(hash, "close()");
	hash->fd = -1;
}

static int mail_hash_file_open(MailHash *hash)
{
	hash->fd = open(hash->filepath, O_RDWR);
	if (hash->fd == -1) {
		if (errno != ENOENT)
			return hash_set_syscall_error(hash, "open()");

		return mail_hash_rebuild(hash);
	}

	return TRUE;
}

static int mmap_update_real(MailHash *hash)
{
	i_assert(!hash->anon_mmap);

	if (hash->mmap_base != NULL) {
		if (munmap(hash->mmap_base, hash->mmap_length) < 0)
			hash_set_syscall_error(hash, "munmap()");
	}

	hash->mmap_base = mmap_rw_file(hash->fd, &hash->mmap_length);
	if (hash->mmap_base == MAP_FAILED) {
		hash->mmap_base = NULL;
		hash->header = NULL;
		hash_set_syscall_error(hash, "mmap()");
		return FALSE;
	}

	return TRUE;
}

static int hash_verify_header(MailHash *hash)
{
	if (hash->mmap_length <= sizeof(MailHashHeader) ||
	    (hash->mmap_length - sizeof(MailHashHeader)) %
	    sizeof(MailHashRecord) != 0) {
		/* hash must be corrupted, rebuilding should have noticed
		   if it was only partially written. */
		hash->header = NULL;
		index_set_error(hash->index, "Corrupted hash file %s: "
				"Invalid file size %"PRIuSIZE_T"",
				hash->filepath, hash->mmap_length);
		return FALSE;
	}

	hash->header = hash->mmap_base;
	hash->size = (hash->mmap_length - sizeof(MailHashHeader)) /
		sizeof(MailHashRecord);

	if (hash->size < MIN_HASH_SIZE || hash->size > MAX_HASH_SIZE) {
		/* invalid size, probably corrupted. */
		hash->header = NULL;
		index_set_error(hash->index, "Corrupted hash file %s: "
				"Invalid size %u", hash->filepath, hash->size);
		return FALSE;
	}

	hash->dirty_mmap = FALSE;
	return TRUE;
}

static int mmap_update(MailHash *hash)
{
	if (hash->fd == -1)
		return hash->anon_mmap;

	/* see if it's been rebuilt */
	if (hash->header->indexid == hash->index->indexid)
		return TRUE;

	if (hash->header->indexid != 0) {
		/* index was just rebuilt. we should have noticed
		   this before at index->set_lock() though. */
		index_set_error(hash->index, "Warning: Inconsistency - Index "
				"%s was rebuilt while we had it open",
				hash->filepath);
		hash->index->inconsistent = TRUE;
		return FALSE;
	}

	mail_hash_file_close(hash);
	if (!mail_hash_file_open(hash))
		return FALSE;

	return mmap_update_real(hash) && hash_verify_header(hash);

}

static void hash_munmap(MailHash *hash)
{
	if (hash->mmap_base == NULL)
		return;

	if (hash->anon_mmap) {
		if (munmap_anon(hash->mmap_base, hash->mmap_length) < 0)
			hash_set_syscall_error(hash, "munmap_anon()");

		hash->anon_mmap = FALSE;
	} else {
		if (munmap(hash->mmap_base, hash->mmap_length) < 0)
			hash_set_syscall_error(hash, "munmap()");
	}

	hash->mmap_base = NULL;
}

static MailHash *mail_hash_new(MailIndex *index)
{
	MailHash *hash;

	hash = i_new(MailHash, 1);
	hash->fd = -1;
	hash->index = index;
	hash->filepath = i_strconcat(index->filepath, ".hash", NULL);
	index->hash = hash;
	return hash;
}

int mail_hash_create(MailIndex *index)
{
	MailHash *hash;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	hash = mail_hash_new(index);
	if (!mail_hash_rebuild(hash) || !hash_verify_header(index->hash)) {
		mail_hash_free(hash);
		return FALSE;
	}

	return TRUE;
}

int mail_hash_open_or_create(MailIndex *index)
{
	MailHash *hash;
	int failed;

	hash = mail_hash_new(index);

	if (!mail_hash_file_open(hash))
		return FALSE;

	if (!mmap_update_real(hash)) {
		/* mmap() failure is fatal */
		mail_hash_free(hash);
		return FALSE;
	}

	/* make sure the header looks fine */
	if (!hash_verify_header(hash))
		failed = TRUE;
	else {
		failed = hash->header->indexid != hash->index->indexid;
		if (failed) {
			index_set_error(hash->index,
					"IndexID mismatch for hash file %s",
					hash->filepath);
		}
	}

	if (failed) {
		/* recreate it */
		hash_munmap(hash);

		return mail_hash_rebuild(hash);
	}

	return TRUE;
}

void mail_hash_free(MailHash *hash)
{
	hash->index->hash = NULL;

	hash_munmap(hash);

	if (hash->fd != -1)
		(void)close(hash->fd);
	i_free(hash->filepath);
	i_free(hash);
}

int mail_hash_sync_file(MailHash *hash)
{
	if (!hash->modified || hash->anon_mmap)
		return TRUE;

	if (msync(hash->mmap_base, hash->mmap_length, MS_SYNC) < 0)
		return hash_set_syscall_error(hash, "msync()");

	hash->modified = FALSE;
	return TRUE;
}

static void hash_build(MailIndex *index, void *mmap_base,
		       unsigned int hash_size)
{
	MailHashHeader *hdr;
        MailHashRecord *rec;
	MailIndexHeader *idx_hdr;
	MailIndexRecord *idx_rec;
	unsigned int i, count;

	/* we have empty hash file mmap()ed now. fill it by reading the
	   messages from index. */
	rec = (MailHashRecord *) ((char *) mmap_base + sizeof(MailHashHeader));
        idx_rec = index->lookup(index, 1);
	for (count = 0; idx_rec != NULL; count++) {
		i = HASH_FUNC(idx_rec->uid) % hash_size;
		rec[i].uid = idx_rec->uid;
		rec[i].position = INDEX_FILE_POSITION(index, idx_rec);
		idx_rec = index->next(index, idx_rec);
	}

	idx_hdr = index->get_header(index);
	if (count != idx_hdr->messages_count) {
		/* mark this as an error but don't fail because of it. */
		index_set_corrupted(index, "Missing messages while rebuilding "
				    "hash file - %u found, header says %u",
				    count, idx_hdr->messages_count);
	}

	/* setup header */
	hdr = mmap_base;
	hdr->indexid = index->indexid;
	hdr->used_records = count;
}

static int hash_rebuild_to_file(MailIndex *index, int fd, const char *path,
				unsigned int hash_size)
{
	void *mmap_base;
	size_t mmap_length, new_size;
	int failed;

	i_assert(hash_size < MAX_HASH_SIZE);

	new_size = HASH_FILE_SIZE(hash_size);

	/* fill the file with zeros */
	if (file_set_size(fd, (off_t)new_size) < 0) {
		index_file_set_syscall_error(index, path, "file_set_size()");
		return FALSE;
	}

	/* now, mmap() it */
	mmap_base = mmap_rw_file(fd, &mmap_length);
	if (mmap_base == MAP_FAILED)
		return index_file_set_syscall_error(index, path, "mmap()");
	i_assert(mmap_length == new_size);

	hash_build(index, mmap_base, hash_size);

	failed = FALSE;
	if (msync(mmap_base, mmap_length, MS_SYNC) < 0) {
		index_file_set_syscall_error(index, path, "msync()");
		failed = TRUE;
	}

	/* we don't want to leave partially written hash around */
	if (!failed && fsync(fd) < 0) {
		index_file_set_syscall_error(index, path, "fsync()");
		failed = TRUE;
	}

	if (munmap(mmap_base, mmap_length) < 0) {
		index_file_set_syscall_error(index, path, "munmap()");
		failed = TRUE;
	}

	return !failed;
}

/* set indexid to 0 in hash file */
static int mail_hash_mark_deleted(MailHash *hash)
{
	MailIndexDataHeader hdr;

	if (hash->fd == -1) {
		/* see if we can open it */
		hash->fd = open(hash->filepath, O_RDWR);
		if (hash->fd == -1)
			return TRUE;
	}

	memset(&hdr, 0, sizeof(hdr));
	if (write_full(hash->fd, &hdr, sizeof(hdr)) < 0)
		return hash_set_syscall_error(hash, "write_full()");

	return TRUE;
}

int mail_hash_rebuild(MailHash *hash)
{
	MailIndexHeader *index_header;
	const char *path;
	unsigned int hash_size;
	int fd, failed;

	if (!hash->index->set_lock(hash->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* figure out size for our hash */
	index_header = hash->index->get_header(hash->index);
	hash_size = primes_closest(index_header->messages_count * 100 /
				   MIN_PERCENTAGE);
	if (hash_size < MIN_HASH_SIZE)
		hash_size = MIN_HASH_SIZE;

	if (hash_size < index_header->messages_count ||
	    hash_size > MAX_HASH_SIZE) {
		/* either our calculation overflowed, or we reached the
		   max. value primes_closest() gave us. and there's more
		   mails - very unlikely. */
		index_set_corrupted(hash->index, "Too many mails in mailbox "
				    "(%u)", index_header->messages_count);
		return FALSE;
	}

	if (hash->index->nodiskspace) {
		/* out of disk space - don't even try building it to file */
		fd = -1;
		errno = ENOSPC;
	} else {
		/* build the hash in a temp file, renaming it to the real hash
		   once finished */
		fd = mail_index_create_temp_file(hash->index, &path);
	}

	if (fd != -1) {
		failed = !hash_rebuild_to_file(hash->index, fd,
					       path, hash_size);

		if (!failed)
			failed = !mail_hash_mark_deleted(hash);

		if (!failed && rename(path, hash->filepath) < 0) {
			index_set_error(hash->index, "rename(%s, %s) failed: "
					"%m", path, hash->filepath);
			failed = TRUE;
		}

		if (failed) {
			int old_errno = errno;

			(void)close(fd);
			(void)unlink(path);
			fd = -1;

			errno = old_errno;
		}
	}

	if (fd == -1) {
		/* building hash to file failed. if it was because there
		   was no space in disk, we could just as well keep it in
		   memory */
		if (errno != ENOSPC)
			return FALSE;

		hash_munmap(hash);

		hash->mmap_length = HASH_FILE_SIZE(hash_size);
		hash->mmap_base = mmap_anon(hash->mmap_length);
		hash_build(hash->index, hash->mmap_base, hash_size);

		/* make sure it doesn't exist anymore */
		(void)unlink(hash->filepath);
	}

	/* switch fds */
	if (hash->fd != -1)
		(void)close(hash->fd);
	hash->fd = fd;
	hash->anon_mmap = fd == -1;
	return TRUE;
}

uoff_t mail_hash_lookup_uid(MailHash *hash, unsigned int uid)
{
        MailHashRecord *rec;
	unsigned int hashidx, idx;

	i_assert(uid > 0);
	i_assert(hash->index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update(hash))
		return 0;

	hashidx = HASH_FUNC(uid) % hash->size;
	rec = (MailHashRecord *) ((char *) hash->mmap_base +
				  sizeof(MailHashHeader));

	/* check from hash index to end of file */
	for (idx = hashidx; idx < hash->size; idx++) {
		if (rec[idx].uid == uid)
			return rec[idx].position;

		if (rec[idx].uid == 0) {
			/* empty hash record - not found. */
			return 0;
		}
	}

	/* check from beginning of file to hash index */
	for (idx = 0; idx < hashidx; idx++) {
		if (rec[idx].uid == uid)
			return rec[idx].position;

		if (rec[idx].uid == 0) {
			/* empty hash record - not found. */
			return 0;
		}
	}

	/* checked through the whole hash file. this really shouldn't happen,
	   we should have rebuilt it long time ago.. */
	return 0;
}

static MailHashRecord *hash_find_uid_or_free(MailHash *hash, unsigned int uid)
{
        MailHashRecord *rec;
	unsigned int hashidx, idx;

	hashidx = HASH_FUNC(uid) % hash->size;
	rec = (MailHashRecord *) ((char *) hash->mmap_base +
				  sizeof(MailHashHeader));

	/* check from hash index to end of file */
	for (idx = hashidx; idx < hash->size; idx++) {
		if (rec[idx].uid == 0 || rec[idx].uid == uid)
			return rec+idx;
	}

	/* check from beginning of file to hash index */
	for (idx = 0; idx < hashidx; idx++) {
		if (rec[idx].uid == 0 || rec[idx].uid == uid)
			return rec+idx;
	}

	/* hash file is full */
	return NULL;
}

void mail_hash_update(MailHash *hash, unsigned int uid, uoff_t pos)
{
	MailHashRecord *rec;
	unsigned int max_used;

	i_assert(uid > 0);
	i_assert(hash->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (!mmap_update(hash))
		return;

	if (hash->header->used_records >
	    hash->size * FORCED_REBUILD_PERCENTAGE / 100) {
		/* we really need a rebuild. */
		if (!mail_hash_rebuild(hash))
			return;
	}

	/* place the hash into first free record after wanted position */
	rec = hash_find_uid_or_free(hash, uid);

	if (rec == NULL) {
		/* this should never happen, we had already checked that
		   at least 1/5 of hash was empty. except, if the header
		   contained invalid record count for some reason. rebuild.. */
		i_error("Hash file was 100%% full, rebuilding");
		if (!mail_hash_rebuild(hash))
			return;

		rec = hash_find_uid_or_free(hash, uid);
		i_assert(rec != NULL);
	}

	if (pos != 0) {
		/* insert/update record */
		if (rec->uid == 0) {
			/* update records count, and see if hash is
			   getting full */
			max_used = hash->size / 100 * REBUILD_PERCENTAGE;
			if (++hash->header->used_records > max_used) {
				hash->index->set_flags |=
					MAIL_INDEX_FLAG_REBUILD_HASH;
			}
		}
		rec->uid = uid;
		rec->position = pos;
	} else {
		/* delete record */
		rec->uid = 0;
		rec->position = 0;
                hash->header->used_records--;
	}

	hash->modified = FALSE;
}
