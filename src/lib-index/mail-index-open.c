/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "file-lock.h"
#include "file-set-size.h"
#include "hostpid.h"
#include "mmap-util.h"
#include "unlink-lockfiles.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-tree.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static int mail_index_open_init(struct mail_index *index,
				enum mail_index_open_flags flags)
{
	struct mail_index_header *hdr;

	hdr = index->header;

	/* update \Recent message counters */
	if ((flags & MAIL_INDEX_OPEN_FLAG_UPDATE_RECENT) != 0 &&
	    hdr->last_nonrecent_uid != hdr->next_uid-1) {
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

	if (hdr->next_uid >= MAX_ALLOWED_UID - 1000) {
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

static int index_open_and_fix(struct mail_index *index,
			      enum mail_index_open_flags flags)
{
	int rebuilt;

	/* open/create the index files */
	if ((flags & _MAIL_INDEX_OPEN_FLAG_CREATING) == 0) {
		if (!mail_index_data_open(index)) {
			if ((index->set_flags & MAIL_INDEX_FLAG_REBUILD) == 0)
				return FALSE;

			/* data file is corrupted, need to rebuild index */
			flags |= _MAIL_INDEX_OPEN_FLAG_CREATING;
			index->set_flags = 0;
			index->inconsistent = FALSE;
		}
	}

	if ((flags & _MAIL_INDEX_OPEN_FLAG_CREATING) != 0) {
		if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
			return FALSE;
		if (!mail_index_data_create(index))
			return FALSE;
	}

	/* custom flags file needs to be open before
	   rebuilding index */
	if (!mail_custom_flags_open_or_create(index))
		return FALSE;

	if ((flags & _MAIL_INDEX_OPEN_FLAG_CREATING) != 0 ||
	    (index->header->flags & MAIL_INDEX_FLAG_REBUILD) != 0) {
		if (!index->rebuild(index))
			return FALSE;

		/* no inconsistency problems since we're still opening
		   the index */
		index->inconsistent = FALSE;
		rebuilt = TRUE;
	} else {
		rebuilt = FALSE;
	}

	if ((flags & _MAIL_INDEX_OPEN_FLAG_CREATING) == 0) {
		if (!mail_tree_open_or_create(index))
			return FALSE;
		if (!mail_modifylog_open_or_create(index))
			return FALSE;
	} else {
		if (!mail_tree_create(index))
			return FALSE;
		if (!mail_modifylog_create(index))
			return FALSE;
	}

	if (index->header->flags & MAIL_INDEX_FLAG_FSCK) {
		/* index needs fscking */
		if (!index->fsck(index))
			return FALSE;
	}

	if ((index->header->flags & MAIL_INDEX_FLAG_REBUILD_TREE) != 0) {
		if (!mail_tree_rebuild(index->tree))
			return FALSE;
	}

	if (!rebuilt) {
		/* sync ourself. do it before updating cache and compression
		   which may happen because of this. */
		if (!index->sync_and_lock(index, MAIL_LOCK_SHARED, NULL) &&
		    !index->nodiskspace)
			return FALSE;

		index->inconsistent = FALSE;
	}

	/* we never want to keep shared lock if syncing happens to set it.
	   either exclusive or nothing (NOTE: drop it directly, not through
	   index->set_lock() so mbox lock won't be affected). */
	if (index->lock_type == MAIL_LOCK_SHARED) {
		if (!mail_index_set_lock(index, MAIL_LOCK_UNLOCK))
			return FALSE;
	}

	if ((flags & MAIL_INDEX_OPEN_FLAG_FAST) == 0) {
		if (index->header->flags & MAIL_INDEX_FLAG_COMPRESS) {
			/* remove deleted blocks from index file */
			if (!mail_index_compress(index))
				return FALSE;
		}

		if (index->header->flags & MAIL_INDEX_FLAG_CACHE_FIELDS) {
			/* need to update cached fields */
			if (!mail_index_update_cache(index))
				return FALSE;
		}

		if (index->header->flags & MAIL_INDEX_FLAG_COMPRESS_DATA) {
			/* remove unused space from index data file.
			   keep after cache updates which may move data
			   and create unused space */
			if (!mail_index_compress_data(index))
				return FALSE;
		}
	}

	if (!mail_index_open_init(index, flags))
		return FALSE;

	return TRUE;
}

static int mail_index_read_header(struct mail_index *index,
				  struct mail_index_header *hdr)
{
	ssize_t ret;

	ret = read(index->fd, hdr, sizeof(*hdr));
	if (ret < 0) {
		index_set_syscall_error(index, "read()");
		return -1;
	}

	if (ret != sizeof(*hdr)) {
		/* missing data */
		return 0;
	}

	return 1;
}

static int mail_index_is_compatible(const struct mail_index_header *hdr)
{
	return hdr->compat_data[0] == MAIL_INDEX_VERSION &&
		hdr->compat_data[1] == MAIL_INDEX_COMPAT_FLAGS &&
		hdr->compat_data[2] == sizeof(unsigned int) &&
		hdr->compat_data[3] == sizeof(time_t) &&
		hdr->compat_data[4] == sizeof(uoff_t) &&
		hdr->compat_data[5] == INDEX_ALIGN_SIZE;
}

static int mail_index_init_file(struct mail_index *index,
				struct mail_index_header *hdr)
{
	hdr->used_file_size = sizeof(*hdr) +
		INDEX_MIN_RECORDS_COUNT * sizeof(struct mail_index_record);

	if (lseek(index->fd, 0, SEEK_SET) < 0) {
		index_set_syscall_error(index, "lseek()");
		return FALSE;
	}

	if (write_full(index->fd, hdr, sizeof(*hdr)) < 0) {
		index_set_syscall_error(index, "write_full()");
		return FALSE;
	}

	if (file_set_size(index->fd, (off_t)hdr->used_file_size) < 0) {
		index_set_syscall_error(index, "file_set_size()");
		return FALSE;
	}

	return TRUE;
}

void mail_index_init_header(struct mail_index *index,
			    struct mail_index_header *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->compat_data[0] = MAIL_INDEX_VERSION;
	hdr->compat_data[1] = MAIL_INDEX_COMPAT_FLAGS;
	hdr->compat_data[2] = sizeof(unsigned int);
	hdr->compat_data[3] = sizeof(time_t);
	hdr->compat_data[4] = sizeof(uoff_t);
	hdr->compat_data[5] = INDEX_ALIGN_SIZE;
	hdr->indexid = ioloop_time;

	/* mark the index requiring rebuild - rebuild() removes this flag
	   when it succeeds */
	hdr->flags = MAIL_INDEX_FLAG_REBUILD;

	if (!index->anon_mmap) {
		/* set the fields we always want to cache,
		   but not if we're building into memory */
		hdr->cache_fields |= index->default_cache_fields;
	}

	hdr->used_file_size = sizeof(struct mail_index_header);
	hdr->uid_validity = ioloop_time;
	hdr->next_uid = 1;
}

static void mail_index_cleanup_temp_files(const char *dir)
{
	unlink_lockfiles(dir, t_strconcat("temp.", my_hostname, NULL),
			 "temp.", time(NULL) - TEMP_FILE_TIMEOUT);
}

void mail_index_init(struct mail_index *index, const char *dir)
{
	size_t len;

	index->fd = -1;

	if (dir != NULL) {
		index->dir = i_strdup(dir);

		len = strlen(index->dir);
		if (index->dir[len-1] == '/')
			index->dir[len-1] = '\0';
	}

	index->mail_read_mmaped = getenv("MAIL_READ_MMAPED") != NULL;
}

static int mail_index_create_memory(struct mail_index *index,
				    enum mail_index_open_flags flags)
{
	if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0)
		return FALSE;

	flags |= _MAIL_INDEX_OPEN_FLAG_CREATING;

	index->mmap_full_length = INDEX_FILE_MIN_SIZE;
	index->mmap_base = mmap_anon(index->mmap_full_length);
	if (index->mmap_base == MAP_FAILED)
		return index_set_error(index, "mmap_anon() failed: %m");

	mail_index_init_header(index, index->mmap_base);
	index->header = index->mmap_base;
	index->mmap_used_length = index->header->used_file_size;

	index->anon_mmap = TRUE;
	index->lock_type = MAIL_LOCK_EXCLUSIVE;
	index->indexid = index->header->indexid;
	index->filepath = i_strdup_printf("(in-memory index for %s)",
					  index->mailbox_path);

	if (!index_open_and_fix(index, flags)) {
		mail_index_close(index);
		return FALSE;
	}

	index->opened = TRUE;
	return TRUE;
}

static int mail_index_open_index(struct mail_index *index,
				 enum mail_index_open_flags flags)
{
	struct mail_index_header hdr;
	int ret;

	if ((flags & _MAIL_INDEX_OPEN_FLAG_CREATING) == 0)
		index->lock_type = MAIL_LOCK_SHARED;
	else
		index->lock_type = MAIL_LOCK_EXCLUSIVE;

	/* if index is being created, we'll wait here until it's finished */
	if (!mail_index_wait_lock(index, MAIL_LOCK_TO_FLOCK(index->lock_type)))
		return FALSE;
#ifdef DEBUG
	if (index->mmap_base != NULL) {
		mprotect(index->mmap_base, index->mmap_used_length,
			 PROT_READ|PROT_WRITE);
	}
#endif

	if ((ret = mail_index_read_header(index, &hdr)) < 0)
		return FALSE;

	if (ret == 0 || !mail_index_is_compatible(&hdr)) {
		if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0)
			return FALSE;

		flags |= _MAIL_INDEX_OPEN_FLAG_CREATING;

		/* so, we're creating the index */
		if (index->lock_type != MAIL_LOCK_EXCLUSIVE) {
			/* have to get exclusive lock first */
			if (!mail_index_wait_lock(index, F_UNLCK))
				return FALSE;
			return mail_index_open_index(index, flags);
		}

		mail_index_init_header(index, &hdr);
		if (!mail_index_init_file(index, &hdr))
			return FALSE;
	}

	index->indexid = hdr.indexid;

	if (!mail_index_mmap_update(index))
		return FALSE;

	if (index->lock_type == MAIL_LOCK_SHARED) {
		/* we don't want to keep the shared lock while opening
		   indexes. opening should work unlocked and some
		   things want exclusive lock */
		if (!mail_index_wait_lock(index, F_UNLCK))
			return FALSE;
		index->lock_type = MAIL_LOCK_UNLOCK;
	}

	if (!index_open_and_fix(index, flags)) {
		if ((index->set_flags & MAIL_INDEX_FLAG_REBUILD) == 0 ||
		    (flags & _MAIL_INDEX_OPEN_FLAG_CREATING) != 0)
			return FALSE;

		/* needs a rebuild */
		if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
			return FALSE;

		flags |= _MAIL_INDEX_OPEN_FLAG_CREATING;
		return mail_index_open_index(index, flags);
	}

	if (!index->set_lock(index, MAIL_LOCK_UNLOCK))
		return FALSE;

	index->opened = TRUE;
	return TRUE;
}

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags)
{
	const char *path;

	i_assert(!index->opened);

	if (index->dir == NULL)
		return mail_index_create_memory(index, flags);

	mail_index_cleanup_temp_files(index->dir);

	/* open/create the file */
        path = t_strconcat(index->dir, "/", INDEX_FILE_PREFIX, NULL);
	if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) != 0)
		index->fd = open(path, O_RDWR | O_CREAT, 0660);
	else
		index->fd = open(path, O_RDWR);
	if (index->fd == -1) {
		if (errno != ENOENT)
			index_file_set_syscall_error(index, path, "open()");
		return mail_index_create_memory(index, flags);
	}

	index->filepath = i_strdup(path);

	if (!mail_index_open_index(index, flags)) {
		mail_index_close(index);
		return mail_index_create_memory(index, flags);
	}

	return TRUE;
}
