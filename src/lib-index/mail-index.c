/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hostpid.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-hash.h"
#include "mail-lockdir.h"
#include "mail-modifylog.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>

static const char *index_file_prefixes[] =
	{ "data", "hash", "log", "log.2", NULL };

static int mmap_update(MailIndex *index)
{
	unsigned int extra;

	if (!index->dirty_mmap) {
		index->header = (MailIndexHeader *) index->mmap_base;
		return TRUE;
	}

	if (index->mmap_base != NULL)
		(void)munmap(index->mmap_base, index->mmap_length);

	index->mmap_base = mmap_rw_file(index->fd, &index->mmap_length);
	if (index->mmap_base == MAP_FAILED) {
		index->mmap_base = NULL;
		index_set_error(index, "index: mmap() failed with file %s: %m",
				index->filepath);
		return FALSE;
	}

	if (index->mmap_length < sizeof(MailIndexHeader)) {
		index_set_error(index, "truncated index file %s",
				index->filepath);
                INDEX_MARK_CORRUPTED(index);
		return FALSE;
	}

	extra = (index->mmap_length - sizeof(MailIndexHeader)) %
		sizeof(MailIndexRecord);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		index->mmap_length -= extra;
		(void)ftruncate(index->fd, (off_t)index->mmap_length);
	}

	index->last_lookup_seq = 0;
	index->last_lookup = NULL;

	index->header = (MailIndexHeader *) index->mmap_base;
	index->dirty_mmap = FALSE;
	return TRUE;
}

void mail_index_close(MailIndex *index)
{
	index->set_flags = 0;
	index->set_cache_fields = 0;

	index->opened = FALSE;
	index->updating = FALSE;
	index->inconsistent = FALSE;
	index->dirty_mmap = TRUE;

	index->lock_type = MAIL_LOCK_UNLOCK;
	index->header = NULL;

	if (index->fd != -1) {
		(void)close(index->fd);
		index->fd = -1;
	}

	if (index->filepath != NULL) {
		i_free(index->filepath);
		index->filepath = NULL;
	}

	if (index->mmap_base != NULL) {
		(void)munmap(index->mmap_base, index->mmap_length);
		index->mmap_base = NULL;
	}

	if (index->data != NULL) {
                mail_index_data_free(index->data);
		index->data = NULL;
	}

	if (index->hash != NULL) {
                mail_hash_free(index->hash);
		index->hash = NULL;
	}

	if (index->modifylog != NULL) {
                mail_modifylog_free(index->modifylog);
		index->modifylog = NULL;
	}

	if (index->error != NULL) {
		i_free(index->error);
		index->error = NULL;
	}
}

int mail_index_sync_file(MailIndex *index)
{
	struct utimbuf ut;
	int failed;

	if (!mail_index_data_sync_file(index->data))
		return FALSE;

	if (index->mmap_base != NULL) {
		if (msync(index->mmap_base, index->mmap_length, MS_SYNC) == -1) {
			index_set_error(index, "msync() failed for %s: %m",
					index->filepath);
			return FALSE;
		}
	}

	failed = FALSE;
	if (index->hash != NULL && !mail_hash_sync_file(index->hash))
		failed = TRUE;
	if (index->modifylog != NULL &&
	    !mail_modifylog_sync_file(index->modifylog))
		failed = TRUE;

	/* keep index's modify stamp same as the sync file's stamp */
	ut.actime = ioloop_time;
	ut.modtime = index->file_sync_stamp;
	if (utime(index->filepath, &ut) == -1) {
		index_set_error(index, "utime() failed for %s: %m",
				index->filepath);
		return FALSE;
	}

	if (fsync(index->fd) == -1) {
		index_set_error(index, "fsync() failed for %s: %m",
				index->filepath);
		return FALSE;
	}

	return !failed;
}

int mail_index_fmsync(MailIndex *index, size_t size)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (msync(index->mmap_base, size, MS_SYNC) == -1) {
		index_set_error(index, "msync() failed for %s: %m",
				index->filepath);
		return FALSE;
	}
	if (fsync(index->fd) == -1) {
		index_set_error(index, "fsync() failed for %s: %m",
				index->filepath);
		return FALSE;
	}

	return TRUE;
}

int mail_index_rebuild_all(MailIndex *index)
{
	if (!index->rebuild(index))
		return FALSE;

	if (!mail_hash_rebuild(index->hash))
		return FALSE;

	return TRUE;
}

static void mail_index_update_header_changes(MailIndex *index)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	if (index->set_flags != 0) {
		index->header->flags |= index->set_flags;
		index->set_flags = 0;
	}

	if (index->set_cache_fields != 0) {
		index->header->cache_fields = index->set_cache_fields;
		index->set_cache_fields = 0;
	}
}

#define MAIL_LOCK_TO_FLOCK(lock_type) \
        ((lock_type) == MAIL_LOCK_UNLOCK ? F_UNLCK : \
		(lock_type) == MAIL_LOCK_SHARED ? F_RDLCK : F_WRLCK)

int mail_index_try_lock(MailIndex *index, MailLockType lock_type)
{
	struct flock fl;

	if (index->lock_type == lock_type)
		return TRUE;

	/* lock whole file */
	fl.l_type = MAIL_LOCK_TO_FLOCK(lock_type);
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(index->fd, F_SETLK, &fl) == -1) {
		if (errno != EINTR && errno != EACCES) {
			index_set_error(index, "fcntl(F_SETLKW, %d) "
					"failed for file %s: %m", fl.l_type,
					index->filepath);
		}
		return FALSE;
	}

	return TRUE;
}

int mail_index_set_lock(MailIndex *index, MailLockType lock_type)
{
	/* yeah, this function is a bit messy. besides locking, it keeps
	   the index synced and in a good shape. */
	MailLockType old_lock_type;
	struct flock fl;
	int ret;

	if (index->inconsistent) {
		/* index is in inconsistent state and nothing else than
		   free() is allowed for it. */
		return FALSE;
	}

	if (index->lock_type == lock_type)
		return TRUE;

	/* shared -> exclusive isn't allowed */
	i_assert(lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->lock_type != MAIL_LOCK_SHARED);

	if (index->lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* releasing exclusive lock */
		index->header->flags &= ~MAIL_INDEX_FLAG_FSCK;

		mail_index_update_header_changes(index);

		/* sync mmaped memory */
		(void)mail_index_sync_file(index);
	}

	if (lock_type != MAIL_LOCK_UNLOCK &&
	    index->lock_type == MAIL_LOCK_UNLOCK && !index->updating) {
		/* unlock -> lock */
		index->updating = TRUE;
		(void)index->sync(index);

		ret = mail_index_set_lock(index, lock_type);
		index->updating = FALSE;
		return ret;
	}

	/* lock whole file */
	fl.l_type = MAIL_LOCK_TO_FLOCK(lock_type);
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(index->fd, F_SETLKW, &fl) == -1) {
		if (errno != EINTR) {
			index_set_error(index, "fcntl(F_SETLKW, %d) "
					"failed for file %s: %m", fl.l_type,
					index->filepath);
			return FALSE;
		}
	}

	if (lock_type == MAIL_LOCK_UNLOCK) {
		/* reset last_lookup so rebuilds don't try to use it */
		index->last_lookup_seq = 0;
		index->last_lookup = NULL;
	}

	old_lock_type = index->lock_type;
	index->lock_type = lock_type;

	if (lock_type != MAIL_LOCK_UNLOCK) {
		/* we're always mmap()ed when we're locked */
		if (!mmap_update(index)) {
			(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);
			return FALSE;
		}

		if (index->indexid != index->header->indexid) {
			/* index was rebuilt, there's no way we can maintain
			   consistency */
			index_set_error(index, "Warning: Inconsistency - Index "
					"%s was rebuilt while we had it open",
					index->filepath);
			index->inconsistent = TRUE;
			return FALSE;
		}
	} else if (old_lock_type == MAIL_LOCK_SHARED) {
		/* releasing shared lock */
		unsigned int old_flags, old_cache;

		old_flags = index->header->flags;
		old_cache = index->header->cache_fields;

		if ((old_flags | index->set_flags) != old_flags ||
		    (old_cache | index->set_cache_fields) != old_cache) {
			/* need to update the header */
			index->updating = TRUE;
			if (mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
				mail_index_update_header_changes(index);
			index->updating = FALSE;

			return mail_index_set_lock(index, MAIL_LOCK_UNLOCK);
		}
	}

	if (lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* while holding exclusive lock, keep the FSCK flag on.
		   when the lock is released, the FSCK flag will also be
		   removed. */
		index->header->flags |= MAIL_INDEX_FLAG_FSCK;
		if (!mail_index_fmsync(index, sizeof(MailIndexHeader))) {
			(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);
			return FALSE;
		}
	}

	if (index->header != NULL && !index->updating &&
	    (index->header->flags & MAIL_INDEX_FLAG_REBUILD) != 0) {
		/* index is corrupted, rebuild it */
		index->updating = TRUE;

		if (lock_type == MAIL_LOCK_SHARED)
			(void)mail_index_set_lock(index, MAIL_LOCK_UNLOCK);

		if (!mail_index_rebuild_all(index))
			return FALSE;

		ret = mail_index_set_lock(index, lock_type);
		index->updating = FALSE;
		return ret;
	}

	if (lock_type == MAIL_LOCK_UNLOCK) {
		/* reset header so it's not used while being unlocked */
		index->last_lookup_seq = 0;
		index->last_lookup = NULL;
	}

	return TRUE;
}

static int delete_index(const char *path)
{
	char tmp[1024];
	int i;

	/* main index */
	if (unlink(path) < 0)
		return FALSE;

	for (i = 0; index_file_prefixes[i] != NULL; i++) {
		i_snprintf(tmp, sizeof(tmp), "%s.%s",
			   path, index_file_prefixes[i]);
		if (unlink(tmp) < 0)
			return FALSE;
		i++;
	}

	return TRUE;
}

static int read_and_verify_header(int fd, MailIndexHeader *hdr,
				  int check_version)
{
	/* read the header */
	if (lseek(fd, 0, SEEK_SET) != 0)
		return FALSE;

	if (read(fd, hdr, sizeof(MailIndexHeader)) != sizeof(MailIndexHeader))
		return FALSE;

	/* check the compatibility */
	return hdr->compat_data[1] == MAIL_INDEX_COMPAT_FLAGS &&
		hdr->compat_data[2] == sizeof(unsigned int) &&
		hdr->compat_data[3] == sizeof(time_t) &&
		hdr->compat_data[4] == sizeof(uoff_t) &&
		hdr->compat_data[5] == MEM_ALIGN_SIZE &&
		(!check_version || hdr->compat_data[0] == MAIL_INDEX_VERSION);
}

/* Returns TRUE if we're compatible with given index file. May delete the
   file if it's from older version. */
static int mail_check_compatible_index(MailIndex *index, const char *path)
{
        MailIndexHeader hdr;
	int fd, compatible;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			index_set_error(index, "Can't open index %s: %m", path);
		return FALSE;
	}

	compatible = read_and_verify_header(fd, &hdr, FALSE);
	if (hdr.compat_data[0] != MAIL_INDEX_VERSION) {
		/* version mismatch */
		compatible = FALSE;
		if (hdr.compat_data[0] < MAIL_INDEX_VERSION) {
			/* of older version, we don't need it anymore */
			(void)delete_index(path);
		}
	}

	(void)close(fd);
	return compatible;
}

/* Returns a file name of compatible index */
static const char *mail_find_index(MailIndex *index)
{
	const char *name;
	char path[1024];

	hostpid_init();

	/* first try .imap.index-<hostname> */
	name = t_strconcat(INDEX_FILE_PREFIX "-", my_hostname, NULL);
	i_snprintf(path, sizeof(path), "%s/%s", index->dir, name);
	if (mail_check_compatible_index(index, path))
		return name;

	/* then try the generic .imap.index */
	name = INDEX_FILE_PREFIX;
	i_snprintf(path, sizeof(path), "%s/%s", index->dir, name);
	if (mail_check_compatible_index(index, path))
		return name;

	return NULL;
}

static int mail_index_open_init(MailIndex *index, int update_recent,
				MailIndexHeader *hdr)
{
	/* update \Recent message counters */
	if (update_recent && hdr->last_nonrecent_uid != hdr->next_uid-1) {
		/* keep last_recent_uid to next_uid-1 */
		if (index->lock_type == MAIL_LOCK_SHARED) {
			if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
				return FALSE;
		}

		if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
			return FALSE;

		index->first_recent_uid = index->header->last_nonrecent_uid+1;
		index->header->last_nonrecent_uid = index->header->next_uid-1;
	} else {
		index->first_recent_uid = hdr->last_nonrecent_uid+1;
	}

	if (hdr->next_uid >= INT_MAX-1024) {
		/* UID values are getting too high, rebuild index */
		index->set_flags |= MAIL_INDEX_FLAG_REBUILD;
	}

	if (index->lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* finally reset the modify log marks, fsck or syncing might
		   have deleted some messages, and since we're only just
		   opening the index, there's no need to remember them */
		if (!mail_modifylog_mark_synced(index->modifylog))
			return FALSE;
	}

	return TRUE;
}

static int mail_index_open_file(MailIndex *index, const char *filename,
				int update_recent)
{
        MailIndexHeader hdr;
	const char *path;
	int fd, failed;

	/* the index file should already be checked that it exists and
	   we're compatible with it. */

	path = t_strconcat(index->dir, "/", filename, NULL);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		index_set_error(index, "Can't open index %s: %m", path);
		return FALSE;
	}

	/* check the compatibility anyway just to be sure */
	if (!read_and_verify_header(fd, &hdr, TRUE)) {
		index_set_error(index, "Non-compatible index file %s", path);
		return FALSE;
	}

	if (index->fd != -1)
		mail_index_close(index);

	index->fd = fd;
	index->filepath = i_strdup(path);
	index->indexid = hdr.indexid;
	index->dirty_mmap = TRUE;
	index->updating = TRUE;

	failed = TRUE;
	do {
		/* open/create the index files */
		if (!mail_index_data_open(index)) {
			if ((index->set_flags & MAIL_INDEX_FLAG_REBUILD) == 0)
				break;

			/* data file is corrupted, need to rebuild index */
			hdr.flags |= MAIL_INDEX_FLAG_REBUILD;
			index->set_flags = 0;

			if (!mail_index_data_create(index))
				break;
		}

		if (hdr.flags & MAIL_INDEX_FLAG_REBUILD) {
			/* index is corrupted, rebuild */
			if (!index->rebuild(index))
				break;
		}

		if (!mail_hash_open_or_create(index))
			break;
		if (!mail_modifylog_open_or_create(index))
			break;

		if (hdr.flags & MAIL_INDEX_FLAG_FSCK) {
			/* index needs fscking */
			if (!index->fsck(index))
				break;
		}

		if (hdr.flags & MAIL_INDEX_FLAG_COMPRESS) {
			/* remove deleted blocks from index file */
			if (!mail_index_compress(index))
				break;
		}

		if (hdr.flags & MAIL_INDEX_FLAG_REBUILD_HASH) {
			if (!mail_hash_rebuild(index->hash))
				break;
		}

		if (hdr.flags & MAIL_INDEX_FLAG_CACHE_FIELDS) {
			/* need to update cached fields */
			if (!mail_index_update_cache(index))
				break;
		}

		if (hdr.flags & MAIL_INDEX_FLAG_COMPRESS_DATA) {
			/* remove unused space from index data file.
			   keep after cache_fields which may move data
			   and create unused space.. */
			if (!mail_index_compress_data(index))
				break;
		}

		if (!index->sync(index))
			break;
		if (!mail_index_open_init(index, update_recent, &hdr))
			break;

		failed = FALSE;
	} while (FALSE);

	index->updating = FALSE;

	if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
		failed = TRUE;

	if (failed)
		mail_index_close(index);

	return !failed;
}

void mail_index_init_header(MailIndexHeader *hdr)
{
	memset(hdr, 0, sizeof(MailIndexHeader));
	hdr->compat_data[0] = MAIL_INDEX_VERSION;
	hdr->compat_data[1] = MAIL_INDEX_COMPAT_FLAGS;
	hdr->compat_data[2] = sizeof(unsigned int);
	hdr->compat_data[3] = sizeof(time_t);
	hdr->compat_data[4] = sizeof(uoff_t);
	hdr->compat_data[5] = MEM_ALIGN_SIZE;
	hdr->indexid = ioloop_time;

	/* mark the index being rebuilt - rebuild() removes this flag
	   when it succeeds */
	hdr->flags = MAIL_INDEX_FLAG_REBUILD;

	/* set the fields we always want to cache - currently nothing
	   except the location. many clients aren't interested about
	   any of the fields. */
	hdr->cache_fields = FIELD_TYPE_LOCATION;

	hdr->uid_validity = ioloop_time;
	hdr->next_uid = 1;
}

static int mail_index_create(MailIndex *index, int *dir_unlocked,
			     int update_recent)
{
        MailIndexHeader hdr;
	const char *path;
	char index_path[1024];
	int fd, len;

	*dir_unlocked = FALSE;

	/* first create the index into temporary file. */
	fd = mail_index_create_temp_file(index, &path);
	if (fd == -1)
		return FALSE;

	/* fill the header */
        mail_index_init_header(&hdr);

	/* write header */
	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		index_set_error(index, "Error writing to temp index %s: %m",
				path);
		(void)close(fd);
		(void)unlink(path);
		return FALSE;
	}

	/* move the temp index into the real one. we also need to figure
	   out what to call ourself on the way. */
	len = i_snprintf(index_path, sizeof(index_path),
			 "%s/" INDEX_FILE_PREFIX, index->dir);
	if (link(path, index_path) == 0)
		(void)unlink(path);
	else {
		if (errno != EEXIST) {
			/* fatal error */
			index_set_error(index, "link(%s, %s) failed: %m",
					path, index_path);
			(void)close(fd);
			(void)unlink(path);
			return FALSE;
		}

		if (getenv("OVERWRITE_INCOMPATIBLE_INDEX") != NULL) {
			/* don't try to support different architectures,
			   just overwrite the index if it's already there. */
		} else {
			/* fallback to .imap.index-hostname - we require each
			   system to have a different hostname so it's safe to
			   override previous index as well */
			hostpid_init();
			i_snprintf(index_path + len, sizeof(index_path)-len,
				   "-%s", my_hostname);
		}

		if (rename(path, index_path) == -1) {
			index_set_error(index, "rename(%s, %s) failed: %m",
					path, index_path);
			(void)close(fd);
			(void)unlink(path);
			return FALSE;
		}

		/* FIXME: race condition here! index may be opened before
		   it's rebuilt. maybe set it locked here, and make it require
		   shared lock when finding the indexes.. */
	}

	if (index->fd != -1)
		mail_index_close(index);

	index->fd = fd;
	index->filepath = i_strdup(index_path);
	index->indexid = hdr.indexid;
	index->updating = TRUE;
	index->dirty_mmap = TRUE;

	/* lock the index file and unlock the directory */
	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE)) {
		index->updating = FALSE;
		return FALSE;
	}

	if (mail_index_lock_dir(index, MAIL_LOCK_UNLOCK))
		*dir_unlocked = TRUE;

	/* create the data file, build the index and hash */
	if (!mail_index_data_create(index) || !index->rebuild(index) ||
	    !mail_hash_create(index) || !mail_modifylog_create(index)) {
		index->updating = FALSE;
		mail_index_close(index);
		return FALSE;
	}
	index->updating = FALSE;

	if (!mail_index_open_init(index, update_recent, index->header)) {
		mail_index_close(index);
		return FALSE;
	}

	/* unlock finally */
	if (!index->set_lock(index, MAIL_LOCK_UNLOCK)) {
		mail_index_close(index);
		return FALSE;
	}

        return TRUE;
}

int mail_index_open(MailIndex *index, int update_recent)
{
	const char *name;

	i_assert(!index->opened);

	name = mail_find_index(index);
	if (name == NULL)
		return FALSE;

	if (!mail_index_open_file(index, name, update_recent))
		return FALSE;

	index->opened = TRUE;
	return TRUE;
}

int mail_index_open_or_create(MailIndex *index, int update_recent)
{
	const char *name;
	int failed, dir_unlocked;

	i_assert(!index->opened);

	/* first see if it's already there */
	name = mail_find_index(index);
	if (name != NULL && mail_index_open_file(index, name, update_recent)) {
		index->opened = TRUE;
		return TRUE;
	}

	/* index wasn't found or it was broken. get exclusive lock and check
	   again, just to make sure we don't end up having two index files
	   due to race condition with another process. */
	if (!mail_index_lock_dir(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	name = mail_find_index(index);
	if (name == NULL || !mail_index_open_file(index, name, update_recent)) {
		/* create/rebuild index */
		failed = !mail_index_create(index, &dir_unlocked,
					    update_recent);
	} else {
		dir_unlocked = FALSE;
		failed = FALSE;
	}

	if (!dir_unlocked && !mail_index_lock_dir(index, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (failed)
		return FALSE;

	index->opened = TRUE;
	return TRUE;
}

int mail_index_verify_hole_range(MailIndex *index)
{
	MailIndexHeader *hdr;
	unsigned int max_records, first_records;

	hdr = index->header;
	if (hdr->first_hole_position == 0)
		return TRUE;

	/* make sure position is valid */
	if (hdr->first_hole_position < sizeof(MailIndexHeader) ||
	    (hdr->first_hole_position -
	     sizeof(MailIndexHeader)) % sizeof(MailIndexRecord) != 0) {
		index_set_error(index, "Error in index file %s: "
				"first_hole_position contains invalid value",
				index->filepath);
		INDEX_MARK_CORRUPTED(index);
		return FALSE;
	}

	/* make sure position is in range.. */
	if (hdr->first_hole_position >= index->mmap_length) {
		index_set_error(index, "Error in index file %s: "
				"first_hole_position points outside file",
				index->filepath);
		INDEX_MARK_CORRUPTED(index);
		return FALSE;
	}

	/* and finally check that first_hole_records is in valid range */
	max_records = MAIL_INDEX_RECORD_COUNT(index);
	first_records = (hdr->first_hole_position -
			 sizeof(MailIndexHeader)) / sizeof(MailIndexRecord);
	if (index->header->first_hole_records > max_records ||
	    first_records + index->header->first_hole_records > max_records) {
		index_set_error(index, "Error in index file %s: "
				"first_hole_records points outside file",
				index->filepath);
		INDEX_MARK_CORRUPTED(index);
		return FALSE;
	}

	return TRUE;
}

static MailIndexRecord *mail_index_lookup_mapped(MailIndex *index,
						 unsigned int lookup_seq)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec, *last_rec;
	unsigned int seq;
	uoff_t seekpos;

	if (lookup_seq == index->last_lookup_seq &&
	    index->last_lookup != NULL && index->last_lookup->uid != 0) {
		/* wanted the same record as last time */
		return index->last_lookup;
	}

	hdr = index->header;
	if (lookup_seq > hdr->messages_count) {
		/* out of range */
		return NULL;
	}

	if (!mail_index_verify_hole_range(index))
		return NULL;

	seekpos = sizeof(MailIndexHeader) +
		(uoff_t)(lookup_seq-1) * sizeof(MailIndexRecord);
	if (seekpos + sizeof(MailIndexRecord) > index->mmap_length) {
		/* out of range */
		return NULL;
	}

	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader));
	last_rec = (MailIndexRecord *) ((char *) index->mmap_base +
					index->mmap_length -
					sizeof(MailIndexRecord));

	if (hdr->first_hole_position == 0 ||
	    hdr->first_hole_position > seekpos) {
		/* easy, it's just at the expected index */
		rec += lookup_seq-1;
		i_assert(rec <= last_rec);

		if (rec->uid == 0) {
			index_set_error(index, "Error in index file %s: "
					"first_hole_position wasn't updated "
					"properly", index->filepath);
			INDEX_MARK_CORRUPTED(index);
			return NULL;
		}
		return rec;
	}

	/* we need to walk through the index to get to wanted position */
	if (lookup_seq > index->last_lookup_seq && index->last_lookup != NULL) {
		/* we want to lookup data after last lookup -
		   this helps us some */
		rec = index->last_lookup;
		seq = index->last_lookup_seq;
	} else {
		/* some mails are deleted, jump after the first known hole
		   and start counting non-deleted messages.. */
		seq = INDEX_POSITION_INDEX(hdr->first_hole_position + 1) + 1;
		rec += seq-1 + hdr->first_hole_records;
	}

	while (seq < lookup_seq && rec <= last_rec) {
		if (rec->uid != 0)
			seq++;
		rec++;
	}

	return rec;
}

MailIndexHeader *mail_index_get_header(MailIndex *index)
{
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	return index->header;
}

MailIndexRecord *mail_index_lookup(MailIndex *index, unsigned int seq)
{
	i_assert(seq > 0);
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (!mmap_update(index))
		return NULL;

	index->last_lookup = mail_index_lookup_mapped(index, seq);
	index->last_lookup_seq = seq;
	return index->last_lookup;
}

MailIndexRecord *mail_index_next(MailIndex *index, MailIndexRecord *rec)
{
	MailIndexRecord *end_rec;

	i_assert(!index->dirty_mmap);
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (rec == NULL)
		return NULL;

	/* go to the next non-deleted record */
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_length);
	while (++rec < end_rec) {
		if (rec->uid != 0)
			return rec;
	}

	return NULL;
}

MailIndexRecord *mail_index_lookup_uid_range(MailIndex *index,
					     unsigned int first_uid,
					     unsigned int last_uid)
{
	MailIndexRecord *rec, *end_rec;
	unsigned int uid, last_try_uid;
	uoff_t pos;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);
	i_assert(first_uid > 0 && last_uid > 0);
	i_assert(first_uid <= last_uid);

	if (!mmap_update(index))
		return NULL;

	if (!mail_index_verify_hole_range(index))
		return NULL;

	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_length);

	/* check if first_uid is the first UID in the index, or an UID
	   before that. this is quite common and hash lookup would be
	   useless to try with those nonexisting old UIDs.. */
	if (index->header->first_hole_position != sizeof(MailIndexHeader)) {
		rec = (MailIndexRecord *) ((char *) index->mmap_base +
					   sizeof(MailIndexHeader));
	} else {
		rec = (MailIndexRecord *) ((char *) index->mmap_base +
					   index->header->first_hole_position +
					   index->header->first_hole_records *
					   sizeof(MailIndexRecord));
	}

	if (rec >= end_rec) {
		/* no messages in index */
		return NULL;
	}

	if (first_uid <= rec->uid) {
		/* yes, first_uid pointed to beginning of index.
		   make sure last_uid is in that range too. */
		return last_uid >= rec->uid ? rec : NULL;
	}

	/* try the few first with hash lookups */
	last_try_uid = last_uid - first_uid < 10 ? last_uid : first_uid + 4;
	for (uid = first_uid; uid <= last_try_uid; uid++) {
		pos = mail_hash_lookup_uid(index->hash, uid);
		if (pos != 0) {
			return (MailIndexRecord *)
				((char *) index->mmap_base + pos);
		}
	}

	if (last_try_uid == last_uid)
		return NULL;

	/* fallback to looking through the whole index - this shouldn't be
	   needed often, so don't bother trying anything too fancy. */
	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader));
	while (rec < end_rec) {
		if (rec->uid != 0) {
			if (rec->uid > last_uid)
				return NULL;

			if (rec->uid >= first_uid)
				return rec;
		}
		rec++;
	}

	return NULL;
}

static MailIndexDataRecord *
index_lookup_data_field(MailIndex *index, MailIndexRecord *rec, MailField field)
{
	MailIndexDataRecord *datarec;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* first check if the field even could be in the file */
	if ((rec->cached_fields & field) != field) {
		if ((index->header->cache_fields & field) == 0) {
			/* no, but make sure the future records will have it.
			   we don't immediately mark the index to cache this
			   field for old messages as some clients never ask
			   the info again */
			index->set_cache_fields |= field;
		} else {
			/* this is at least the second time it's being asked,
			   make sure it'll be cached soon. */
			index->set_flags |= MAIL_INDEX_FLAG_CACHE_FIELDS;
		}

		return NULL;
	}

	datarec = mail_index_data_lookup(index->data, rec, field);
	if (datarec == NULL) {
		/* corrupted, the field should have been there */
		index_set_error(index, "Error in index file %s: "
				"Field not found from data file",
				index->filepath);
		INDEX_MARK_CORRUPTED(index);
		return NULL;
	}

	return datarec;
}

const char *mail_index_lookup_field(MailIndex *index, MailIndexRecord *rec,
				    MailField field)
{
	MailIndexDataRecord *datarec;

	datarec = index_lookup_data_field(index, rec, field);
	if (datarec == NULL)
		return NULL;

	if (!mail_index_data_record_verify(index->data, datarec)) {
		/* index is corrupted, it will be rebuilt */
		return NULL;
	}

	return datarec->data;
}

const void *mail_index_lookup_field_raw(MailIndex *index, MailIndexRecord *rec,
					MailField field, unsigned int *size)
{
	MailIndexDataRecord *datarec;

	datarec = index_lookup_data_field(index, rec, field);
	if (datarec == NULL) {
		*size = 0;
		return NULL;
	}

	*size = datarec->full_field_size;
	return datarec->data;
}

unsigned int mail_index_get_sequence(MailIndex *index, MailIndexRecord *rec)
{
	MailIndexRecord *seekrec;
	unsigned int seq;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	if (rec == index->last_lookup) {
		/* same as last lookup sequence - too easy */
		return index->last_lookup_seq;
	}

	if (index->header->first_hole_position == 0) {
		/* easy, it's just at the expected index */
		return INDEX_POSITION_INDEX(
			INDEX_FILE_POSITION(index, rec)) + 1;
	}

	if (!mail_index_verify_hole_range(index))
		return 0;

	seekrec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->header->first_hole_position);
	if (rec < seekrec) {
		/* record before first hole */
		return INDEX_POSITION_INDEX(
			INDEX_FILE_POSITION(index, rec)) + 1;
	}

	/* we know the sequence after the first hole - skip to there and
	   start browsing the records until ours is found */
	seq = INDEX_POSITION_INDEX(INDEX_FILE_POSITION(index, seekrec))+1;
	seekrec += index->header->first_hole_records;

	for (; seekrec < rec; seekrec++) {
		if (seekrec->uid != 0)
			seq++;
	}

	return seq;
}

void mail_index_mark_flag_changes(MailIndex *index, MailIndexRecord *rec,
				  MailFlags old_flags, MailFlags new_flags)
{
	if ((old_flags & MAIL_SEEN) == 0 && (new_flags & MAIL_SEEN)) {
		/* unseen -> seen */
		index->header->seen_messages_count++;
	} else if ((old_flags & MAIL_SEEN) && (new_flags & MAIL_SEEN) == 0) {
		/* seen -> unseen */
		if (index->header->seen_messages_count ==
		    index->header->messages_count) {
			/* this is the first unseen message */
                        index->header->first_unseen_uid_lowwater = rec->uid;
		} else if (rec->uid < index->header->first_unseen_uid_lowwater)
			index->header->first_unseen_uid_lowwater = rec->uid;

		if (index->header->seen_messages_count == 0)
                        INDEX_MARK_CORRUPTED(index);
		else
			index->header->seen_messages_count--;
	} else if ((old_flags & MAIL_DELETED) == 0 &&
		   (new_flags & MAIL_DELETED)) {
		/* undeleted -> deleted */
		index->header->deleted_messages_count++;

		if (index->header->deleted_messages_count == 1) {
			/* this is the first deleted message */
			index->header->first_deleted_uid_lowwater = rec->uid;
		} else if (rec->uid < index->header->first_deleted_uid_lowwater)
			index->header->first_deleted_uid_lowwater = rec->uid;
	} else if ((old_flags & MAIL_DELETED) &&
		   (new_flags & MAIL_DELETED) == 0) {
		/* deleted -> undeleted */
		if (index->header->deleted_messages_count == 0)
                        INDEX_MARK_CORRUPTED(index);
		else
			index->header->deleted_messages_count--;
	}
}

static void update_first_hole_records(MailIndex *index)
{
        MailIndexRecord *rec, *end_rec;

	/* see if first_hole_records can be grown */
	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   index->header->first_hole_position) +
		index->header->first_hole_records;
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_length);
	while (rec < end_rec && rec->uid == 0) {
		index->header->first_hole_records++;
		rec++;
	}
}

static int mail_index_truncate(MailIndex *index)
{
	/* truncate index file */
	if (ftruncate(index->fd, (off_t)index->header->first_hole_position) < 0)
		return FALSE;

	/* update header */
	index->header->first_hole_position = 0;
	index->header->first_hole_records = 0;

	if (index->header->messages_count == 0) {
		/* all mail was deleted, truncate data file */
		if (!mail_index_data_reset(index->data))
			return FALSE;
	}

	index->dirty_mmap = TRUE;
	if (!mmap_update(index))
		return FALSE;

	return TRUE;
}

int mail_index_expunge(MailIndex *index, MailIndexRecord *rec,
		       unsigned int seq, int external_change)
{
	MailIndexHeader *hdr;
	uoff_t pos;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(seq != 0);
	i_assert(rec->uid != 0);

	if (seq != 0 && index->modifylog != NULL) {
		if (!mail_modifylog_add_expunge(index->modifylog, seq,
						rec->uid, external_change))
			return FALSE;
	}

	/* expunge() may be called while index is being rebuilt and when
	   there's no hash yet */
	if (index->hash != NULL)
		mail_hash_update(index->hash, rec->uid, 0);

	/* setting UID to 0 is enough for deleting the mail from index */
	rec->uid = 0;

	/* update last_lookup_seq */
	if (seq != 0) {
		/* note that last_lookup can be left to point to
		   invalid record so that next() works properly */
		if (seq == index->last_lookup_seq)
			index->last_lookup = NULL;
		else if (seq < index->last_lookup_seq)
			index->last_lookup_seq--;
	}

	if (!mail_index_verify_hole_range(index))
		return FALSE;

	hdr = index->header;

	/* update first hole */
	pos = INDEX_FILE_POSITION(index, rec);
	if (hdr->first_hole_position < sizeof(MailIndexRecord)) {
		/* first deleted message in index */
		hdr->first_hole_position = pos;
		hdr->first_hole_records = 1;
	} else if (hdr->first_hole_position - sizeof(MailIndexRecord) == pos) {
		/* deleted the previous record before hole */
		hdr->first_hole_position -= sizeof(MailIndexRecord);
		hdr->first_hole_records++;
	} else if (hdr->first_hole_position +
		   (hdr->first_hole_records * sizeof(MailIndexRecord)) == pos) {
		/* deleted the next record after hole */
		hdr->first_hole_records++;
		update_first_hole_records(index);
	} else {
		/* second hole coming to index file, the index now needs to
		   be compressed to keep high performance */
		index->set_flags |= MAIL_INDEX_FLAG_COMPRESS;

		if (hdr->first_hole_position > pos) {
			/* new hole before the old hole */
			hdr->first_hole_position = pos;
			hdr->first_hole_records = 1;
		}
	}

	/* update message counts */
	if (hdr->messages_count == 0) {
		/* corrupted */
		index_set_error(index, "Error in index file %s: "
				"Header says there's no mail while expunging",
				index->filepath);
		INDEX_MARK_CORRUPTED(index);
		return FALSE;
	}

	hdr->messages_count--;
	mail_index_mark_flag_changes(index, rec, rec->msg_flags, 0);

	if ((hdr->first_hole_position - sizeof(MailIndexHeader)) /
	    sizeof(MailIndexRecord) == hdr->messages_count) {
		/* the hole reaches end of file, truncate it */
		(void)mail_index_truncate(index);
	} else {
		/* update deleted_space in data file */
		(void)mail_index_data_add_deleted_space(index->data,
							rec->data_size);
	}

	return TRUE;
}

int mail_index_update_flags(MailIndex *index, MailIndexRecord *rec,
			    unsigned int seq, MailFlags flags,
			    int external_change)
{
	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(seq != 0);

	if (flags == rec->msg_flags)
		return TRUE; /* no changes */

        mail_index_mark_flag_changes(index, rec, rec->msg_flags, flags);

	rec->msg_flags = flags;
	return index->modifylog == NULL ? TRUE :
		mail_modifylog_add_flags(index->modifylog, seq,
					 rec->uid, external_change);
}

int mail_index_append(MailIndex *index, MailIndexRecord **rec)
{
	off_t pos;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	(*rec)->uid = index->header->next_uid++;

	pos = lseek(index->fd, 0, SEEK_END);
	if (pos < 0) {
		index_set_error(index, "lseek() failed with file %s: %m",
				index->filepath);
		return FALSE;
	}

	if (write_full(index->fd, *rec, sizeof(MailIndexRecord)) < 0) {
		index_set_error(index, "Error appending to file %s: %m",
				index->filepath);
		return FALSE;
	}

	index->header->messages_count++;
        mail_index_mark_flag_changes(index, *rec, 0, (*rec)->msg_flags);

	if (index->hash != NULL)
		mail_hash_update(index->hash, (*rec)->uid, (uoff_t)pos);

	index->dirty_mmap = TRUE;
	if (!mmap_update(index))
		return FALSE;

	*rec = (MailIndexRecord *) ((char *) index->mmap_base + pos);
	return TRUE;
}

const char *mail_index_get_last_error(MailIndex *index)
{
	return index->error;
}

int mail_index_is_inconsistency_error(MailIndex *index)
{
	return index->inconsistent;
}
