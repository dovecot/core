/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "hostpid.h"
#include "mmap-util.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-hash.h"
#include "mail-lockdir.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static const char *index_file_prefixes[] =
	{ "data", "hash", "log", "log.2", NULL };

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
			index_file_set_syscall_error(index, path, "open()");
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

static int mail_index_open_init(MailIndex *index, MailIndexHeader *hdr,
				int update_recent)
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

static int index_open_and_fix(MailIndex *index, MailIndexHeader *hdr,
			      int update_recent)
{
	/* open/create the index files */
	if (!mail_index_data_open(index)) {
		if ((index->set_flags & MAIL_INDEX_FLAG_REBUILD) == 0)
			return FALSE;

		/* data file is corrupted, need to rebuild index */
		hdr->flags |= MAIL_INDEX_FLAG_REBUILD;
		index->set_flags = 0;

		if (!mail_index_data_create(index))
			return FALSE;
	}

	/* custom flags file needs to be open before
	   rebuilding index */
	if (!mail_custom_flags_open_or_create(index))
		return FALSE;

	if (hdr->flags & MAIL_INDEX_FLAG_REBUILD) {
		/* index is corrupted, rebuild */
		if (!index->rebuild(index))
			return FALSE;

		/* no inconsistency problems while still opening
		   the index */
		index->inconsistent = FALSE;
	}

	if (!mail_hash_open_or_create(index))
		return FALSE;
	if (!mail_modifylog_open_or_create(index))
		return FALSE;

	if (hdr->flags & MAIL_INDEX_FLAG_FSCK) {
		/* index needs fscking */
		if (!index->fsck(index))
			return FALSE;
	}

	if (hdr->flags & MAIL_INDEX_FLAG_COMPRESS) {
		/* remove deleted blocks from index file */
		if (!mail_index_compress(index))
			return FALSE;
	}

	if (hdr->flags & MAIL_INDEX_FLAG_REBUILD_HASH) {
		if (!mail_hash_rebuild(index->hash))
			return FALSE;
	}

	/* sync before updating cached fields so it won't print
	   warnings if mails were deleted */
	if (!index->sync(index))
		return FALSE;

	if (hdr->flags & MAIL_INDEX_FLAG_CACHE_FIELDS) {
		/* need to update cached fields */
		if (!mail_index_update_cache(index))
			return FALSE;
	}

	if (hdr->flags & MAIL_INDEX_FLAG_COMPRESS_DATA) {
		/* remove unused space from index data file.
		   keep after cache_fields which may move data
		   and create unused space.. */
		if (!mail_index_compress_data(index))
			return FALSE;
	}

	if (!mail_index_open_init(index, hdr, update_recent))
		return FALSE;

	if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
		return FALSE;

	return TRUE;
}

static int mail_index_open_file(MailIndex *index, const char *path,
				int update_recent)
{
        MailIndexHeader hdr;
	int fd;

	/* the index file should already be checked that it exists and
	   we're compatible with it. */

	fd = open(path, O_RDWR);
	if (fd == -1)
		return index_file_set_syscall_error(index, path, "open()");

	/* if index is being created, we'll wait here until it's finished */
	if (file_wait_lock(fd, F_RDLCK) < 0) {
		index_file_set_syscall_error(index, path, "file_wait_lock()");
		(void)close(fd);
		return FALSE;
	}

	/* check the compatibility anyway just to be sure */
	if (!read_and_verify_header(fd, &hdr, TRUE)) {
		index_set_error(index, "Non-compatible index file %s", path);
		(void)close(fd);
		return FALSE;
	}

	if (file_wait_lock(fd, F_UNLCK) < 0) {
		index_file_set_syscall_error(index, path, "file_wait_lock()");
		(void)close(fd);
		return FALSE;
	}

	index->fd = fd;
	index->filepath = i_strdup(path);
	index->indexid = hdr.indexid;

	if (!index_open_and_fix(index, &hdr, update_recent)) {
		mail_index_close(index);
		return FALSE;
	}

	return TRUE;
}

static int mail_index_init_new_file(MailIndex *index, MailIndexHeader *hdr,
				    int fd, const char *path,
				    const char **index_path)
{
	off_t fsize;

	*index_path = NULL;

	if (write_full(fd, hdr, sizeof(MailIndexHeader)) < 0) {
		index_file_set_syscall_error(index, path, "write_full()");
		return FALSE;
	}

	fsize = sizeof(MailIndexHeader) +
		INDEX_MIN_RECORDS_COUNT * sizeof(MailIndexRecord);
	if (file_set_size(fd, (off_t)fsize) < 0) {
		index_file_set_syscall_error(index, path, "file_set_size()");
		return FALSE;
	}

	if (file_wait_lock(fd, F_WRLCK) < 0) {
		index_file_set_syscall_error(index, path, "file_wait_lock()");
		return FALSE;
	}

	/* move the temp index into the real one. we also need to figure
	   out what to call ourself on the way. */
	*index_path = t_strconcat(index->dir, "/"INDEX_FILE_PREFIX, NULL);
	if (link(path, *index_path) == 0) {
		if (unlink(path) < 0) {
			/* doesn't really matter, log anyway */
			index_file_set_syscall_error(index, path, "unlink()");
		}
	} else {
		if (errno != EEXIST) {
			/* fatal error */
			index_set_error(index, "link(%s, %s) failed: %m",
					path, *index_path);
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

			*index_path = t_strconcat(*index_path, "-",
						  my_hostname, NULL);
		}

		if (rename(path, *index_path) < 0) {
			index_set_error(index, "rename(%s, %s) failed: %m",
					path, *index_path);
			return FALSE;
		}
	}

	return TRUE;
}

static int mail_index_create(MailIndex *index, int *dir_unlocked,
			     int update_recent)
{
	MailIndexHeader hdr;
	const char *path, *index_path;
	int fd;

	*dir_unlocked = FALSE;
	index_path = NULL;

	mail_index_init_header(&hdr);

	if (index->nodiskspace) {
		/* don't even bother trying to create it */
		fd = -1;
	} else {
		/* first create the index into temporary file. */
		fd = mail_index_create_temp_file(index, &path);
		if (fd != -1) {
			if (!mail_index_init_new_file(index, &hdr, fd,
						      path, &index_path)) {
				int old_errno = errno;

				(void)close(fd);
				(void)unlink(path);
				fd = -1;

				errno = old_errno;
			}
		}

		if (fd == -1 && errno != ENOSPC) {
			/* fatal failure */
			return FALSE;
		}
	}

	if (fd == -1) {
		/* no space for index files, keep it in memory */
		index->mmap_full_length = INDEX_FILE_MIN_SIZE;
		index->mmap_base = mmap_anon(index->mmap_full_length);

		memcpy(index->mmap_base, &hdr, sizeof(hdr));
		index->header = index->mmap_base;
		index->mmap_used_length = index->header->used_file_size;

		index->anon_mmap = TRUE;
		index->filepath = i_strdup("(in-memory index)");
	} else {
		index->filepath = i_strdup(index_path);
	}

	index->fd = fd;
	index->indexid = hdr.indexid;

	/* the fd is actually already locked, now we're just making it
	   clear to the indexing code. */
	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE)) {
		mail_index_close(index);
		return FALSE;
	}

	/* it's not good to keep the directory locked too long. our index file
	   is locked which is enough. */
	if (!*dir_unlocked && mail_index_lock_dir(index, MAIL_LOCK_UNLOCK))
		*dir_unlocked = TRUE;

	do {
		if (!mail_custom_flags_open_or_create(index))
			break;
		if (!mail_index_data_create(index))
			break;

		if (!index->rebuild(index)) {
			if (!index->anon_mmap && index->nodiskspace) {
				/* we're out of disk space, keep it in
				   memory this time */
				mail_index_close(index);

                                index->nodiskspace = TRUE;
				return mail_index_create(index, dir_unlocked,
							 update_recent);
			}
			break;
		}

		if (!mail_hash_create(index))
			break;
		if (!mail_modifylog_create(index))
			break;

		index->inconsistent = FALSE;

		if (!mail_index_open_init(index, index->header, update_recent))
			break;

		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			break;

		return TRUE;
	} while (0);

	mail_index_close(index);
	return FALSE;
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

	/* mark the index requiring rebuild - rebuild() removes this flag
	   when it succeeds */
	hdr->flags = MAIL_INDEX_FLAG_REBUILD;

	/* set the fields we always want to cache */
	hdr->cache_fields |= FIELD_TYPE_LOCATION | FIELD_TYPE_MESSAGEPART;

	hdr->used_file_size = sizeof(MailIndexHeader);
	hdr->uid_validity = ioloop_time;
	hdr->next_uid = 1;
}

int mail_index_open(MailIndex *index, int update_recent)
{
	const char *name, *path;

	i_assert(!index->opened);

	/* this isn't initialized anywhere else */
	index->fd = -1;

	name = mail_find_index(index);
	if (name == NULL)
		return FALSE;

	path = t_strconcat(index->dir, "/", name, NULL);
	if (!mail_index_open_file(index, path, update_recent))
		return FALSE;

	index->opened = TRUE;
	return TRUE;
}

int mail_index_open_or_create(MailIndex *index, int update_recent)
{
	int failed, dir_unlocked;

	i_assert(!index->opened);

	if (mail_index_open(index, update_recent))
		return TRUE;

	/* index wasn't found or it was broken. lock the directory and check
	   again, just to make sure we don't end up having two index files
	   due to race condition with another process. */
	if (!mail_index_lock_dir(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (mail_index_open(index, update_recent)) {
		dir_unlocked = FALSE;
		failed = FALSE;
	} else {
		failed = !mail_index_create(index, &dir_unlocked,
					    update_recent);
	}

	if (!dir_unlocked && !mail_index_lock_dir(index, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (failed)
		return FALSE;

	index->opened = TRUE;
	return TRUE;
}
