/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "nfs-workarounds.h"
#include "mmap-util.h"
#include "read-full.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log-private.h"
#include "ioloop.h"

static void mail_index_map_copy_hdr(struct mail_index_map *map,
				    const struct mail_index_header *hdr)
{
	if (hdr->base_header_size < sizeof(map->hdr)) {
		/* header smaller than ours, make a copy so our newer headers
		   won't have garbage in them */
		i_zero(&map->hdr);
		memcpy(&map->hdr, hdr, hdr->base_header_size);
	} else {
		map->hdr = *hdr;
	}

	/* FIXME: backwards compatibility, remove later. In case this index is
	   accessed with Dovecot v1.0, avoid recent message counter errors. */
	map->hdr.unused_old_recent_messages_count = 0;
}

static int mail_index_mmap(struct mail_index_map *map, uoff_t file_size)
{
	struct mail_index *index = map->index;
	struct mail_index_record_map *rec_map = map->rec_map;
	const struct mail_index_header *hdr;
	const char *error;

	i_assert(rec_map->mmap_base == NULL);

	buffer_free(&rec_map->buffer);
	if (file_size > SSIZE_T_MAX) {
		/* too large file to map into memory */
		mail_index_set_error(index, "Index file too large: %s",
				     index->filepath);
		return -1;
	}

	rec_map->mmap_base = mmap(NULL, file_size, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE, index->fd, 0);
	if (rec_map->mmap_base == MAP_FAILED) {
		rec_map->mmap_base = NULL;
		if (ioloop_time != index->last_mmap_error_time) {
			index->last_mmap_error_time = ioloop_time;
			mail_index_set_syscall_error(index, t_strdup_printf(
				"mmap(size=%"PRIuUOFF_T")", file_size));
		}
		return -1;
	}
	rec_map->mmap_size = file_size;

	hdr = rec_map->mmap_base;
	if (rec_map->mmap_size >
	    offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (rec_map->mmap_size < MAIL_INDEX_HEADER_MIN_SIZE) {
		mail_index_set_error(index, "Corrupted index file %s: "
				     "File too small (%zu)",
				     index->filepath, rec_map->mmap_size);
		return 0;
	}

	if (!mail_index_check_header_compat(index, hdr, rec_map->mmap_size, &error)) {
		/* Can't use this file */
		mail_index_set_error(index, "Corrupted index file %s: %s",
				     index->filepath, error);
		return 0;
	}

	rec_map->mmap_used_size = hdr->header_size +
		hdr->messages_count * hdr->record_size;

	if (rec_map->mmap_used_size <= rec_map->mmap_size)
		rec_map->records_count = hdr->messages_count;
	else {
		rec_map->records_count =
			(rec_map->mmap_size - hdr->header_size) /
			hdr->record_size;
		rec_map->mmap_used_size = hdr->header_size +
			rec_map->records_count * hdr->record_size;
		mail_index_set_error(index, "Corrupted index file %s: "
				     "messages_count too large (%u > %u)",
				     index->filepath, hdr->messages_count,
				     rec_map->records_count);
	}

	mail_index_map_copy_hdr(map, hdr);

	map->hdr_base = rec_map->mmap_base;
	rec_map->records = PTR_OFFSET(rec_map->mmap_base, map->hdr.header_size);
	return 1;
}

static int mail_index_read_header(struct mail_index *index,
				  void *buf, size_t buf_size, size_t *pos_r)
{
	size_t pos;
	int ret;

	memset(buf, 0, sizeof(struct mail_index_header));

        /* try to read the whole header, but it's not necessarily an error to
	   read less since the older versions of the index format could be
	   smaller. Request reading up to buf_size, but accept if we only got
	   the header. */
        pos = 0;
	do {
		ret = pread(index->fd, PTR_OFFSET(buf, pos),
			    buf_size - pos, pos);
		if (ret > 0)
			pos += ret;
	} while (ret > 0 && pos < sizeof(struct mail_index_header));

	*pos_r = pos;
	return ret;
}

static int
mail_index_try_read_map(struct mail_index_map *map,
			uoff_t file_size, bool *retry_r, bool try_retry)
{
	struct mail_index *index = map->index;
	const struct mail_index_header *hdr;
	unsigned char read_buf[IO_BLOCK_SIZE];
	const char *error;
	const void *buf;
	void *data = NULL;
	ssize_t ret;
	size_t pos, records_size, initial_buf_pos = 0;
	unsigned int records_count = 0, extra;

	i_assert(map->rec_map->mmap_base == NULL);

	*retry_r = FALSE;
	ret = mail_index_read_header(index, read_buf, sizeof(read_buf), &pos);
	buf = read_buf; hdr = buf;

	if (pos > (ssize_t)offsetof(struct mail_index_header, major_version) &&
	    hdr->major_version != MAIL_INDEX_MAJOR_VERSION) {
		/* major version change - handle silently */
		return 0;
	}

	if (ret >= 0 && pos >= MAIL_INDEX_HEADER_MIN_SIZE &&
	    (ret > 0 || pos >= hdr->base_header_size)) {
		if (!mail_index_check_header_compat(index, hdr, file_size, &error)) {
			/* Can't use this file */
			mail_index_set_error(index, "Corrupted index file %s: %s",
					     index->filepath, error);
			return 0;
		}

		initial_buf_pos = pos;
		if (pos > hdr->header_size)
			pos = hdr->header_size;

		/* place the base header into memory. */
		buffer_set_used_size(map->hdr_copy_buf, 0);
		buffer_append(map->hdr_copy_buf, buf, pos);

		if (pos != hdr->header_size) {
			/* @UNSAFE: read the rest of the header into memory */
			data = buffer_append_space_unsafe(map->hdr_copy_buf,
							  hdr->header_size -
							  pos);
			ret = pread_full(index->fd, data,
					 hdr->header_size - pos, pos);
		}
	}

	if (ret > 0) {
		/* header read, read the records now. */
		records_size = (size_t)hdr->messages_count * hdr->record_size;
		records_count = hdr->messages_count;

		if (file_size - hdr->header_size < records_size ||
		    (hdr->record_size != 0 &&
		     records_size / hdr->record_size != hdr->messages_count)) {
			records_count = (file_size - hdr->header_size) /
				hdr->record_size;
			records_size = (size_t)records_count * hdr->record_size;
			mail_index_set_error(index, "Corrupted index file %s: "
				"messages_count too large (%u > %u)",
				index->filepath, hdr->messages_count,
				records_count);
		}

		if (map->rec_map->buffer == NULL) {
			map->rec_map->buffer =
				buffer_create_dynamic(default_pool,
						      records_size);
		}

		/* @UNSAFE */
		buffer_set_used_size(map->rec_map->buffer, 0);
		if (initial_buf_pos <= hdr->header_size)
			extra = 0;
		else {
			extra = initial_buf_pos - hdr->header_size;
			buffer_append(map->rec_map->buffer,
				      CONST_PTR_OFFSET(buf, hdr->header_size),
				      extra);
		}
		if (records_size > extra) {
			data = buffer_append_space_unsafe(map->rec_map->buffer,
							  records_size - extra);
			ret = pread_full(index->fd, data, records_size - extra,
					 hdr->header_size + extra);
		}
	}

	if (ret < 0) {
		if (errno == ESTALE && try_retry) {
			/* a new index file was renamed over this one. */
			*retry_r = TRUE;
			return 0;
		}
		mail_index_set_syscall_error(index, "pread_full()");
		return -1;
	}
	if (ret == 0) {
		mail_index_set_error(index,
			"Corrupted index file %s: File too small",
			index->filepath);
		return 0;
	}

	map->rec_map->records =
		buffer_get_modifiable_data(map->rec_map->buffer, NULL);
	map->rec_map->records_count = records_count;

	mail_index_map_copy_hdr(map, hdr);
	map->hdr_base = map->hdr_copy_buf->data;
	i_assert(map->hdr_copy_buf->used == map->hdr.header_size);
	return 1;
}

static int mail_index_read_map(struct mail_index_map *map, uoff_t file_size)
{
	struct mail_index *index = map->index;
	mail_index_sync_lost_handler_t *const *handlerp;
	struct stat st;
	unsigned int i;
	int ret;
	bool try_retry, retry;

	/* notify all "sync lost" handlers */
	array_foreach(&index->sync_lost_handlers, handlerp)
		(**handlerp)(index);

	for (i = 0;; i++) {
		try_retry = i < MAIL_INDEX_ESTALE_RETRY_COUNT;
		if (file_size == (uoff_t)-1) {
			/* fstat() below failed */
			ret = 0;
			retry = try_retry;
		} else {
			ret = mail_index_try_read_map(map, file_size,
						      &retry, try_retry);
		}
		if (ret != 0 || !retry)
			break;

		/* ESTALE - reopen index file */
		mail_index_close_file(index);

                ret = mail_index_try_open_only(index);
		if (ret <= 0) {
			if (ret == 0) {
				/* the file was lost */
				errno = ENOENT;
				mail_index_set_syscall_error(index, "open()");
			}
			return -1;
		}

		if (fstat(index->fd, &st) == 0)
			file_size = st.st_size;
		else {
			if (!ESTALE_FSTAT(errno)) {
				mail_index_set_syscall_error(index, "fstat()");
				return -1;
			}
			file_size = (uoff_t)-1;
		}
	}
	return ret;
}

/* returns -1 = error, 0 = index files are unusable,
   1 = index files are usable or at least repairable */
static int
mail_index_map_latest_file(struct mail_index *index, const char **reason_r)
{
	struct mail_index_map *old_map, *new_map;
	struct stat st;
	uoff_t file_size;
	bool use_mmap, unusable = FALSE;
	const char *error;
	int ret, try;

	*reason_r = NULL;

	ret = mail_index_reopen_if_changed(index, reason_r);
	if (ret <= 0) {
		if (ret < 0)
			return -1;

		/* the index file is lost/broken. let's hope that we can
		   build it from the transaction log. */
		return 1;
	}
	i_assert(index->fd != -1);

	if ((index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0)
		nfs_flush_attr_cache_fd_locked(index->filepath, index->fd);

	if (fstat(index->fd, &st) == 0)
		file_size = st.st_size;
	else {
		if (!ESTALE_FSTAT(errno)) {
			mail_index_set_syscall_error(index, "fstat()");
			return -1;
		}
		file_size = (uoff_t)-1;
	}

	/* mmaping seems to be slower than just reading the file, so even if
	   mmap isn't disabled don't use it unless the file is large enough */
	use_mmap = (index->flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) == 0 &&
		file_size != (uoff_t)-1 && file_size > MAIL_INDEX_MMAP_MIN_SIZE;

	new_map = mail_index_map_alloc(index);
	if (use_mmap) {
		ret = mail_index_mmap(new_map, file_size);
	} else {
		ret = mail_index_read_map(new_map, file_size);
	}
	if (ret == 0) {
		/* the index files are unusable */
		unusable = TRUE;
	}

	for (try = 0; ret > 0; try++) {
		/* make sure the header is ok before using this mapping */
		ret = mail_index_map_check_header(new_map, &error);
		if (ret < 0) {
			mail_index_set_error(index,
				"Corrupted index file %s: %s",
				index->filepath, error);
		}
		if (ret > 0) T_BEGIN {
			if (mail_index_map_parse_extensions(new_map) < 0)
				ret = 0;
			else if (mail_index_map_parse_keywords(new_map) < 0)
				ret = 0;
		} T_END;
		if (ret != 0 || try == 2) {
			if (ret < 0) {
				*reason_r = "Corrupted index file";
				unusable = TRUE;
				ret = 0;
			}
			break;
		}

		/* fsck and try again */
		old_map = index->map;
		index->map = new_map;
		if (mail_index_fsck(index) < 0) {
			ret = -1;
			break;
		}

		/* fsck replaced the map */
		new_map = index->map;
		index->map = old_map;
	}
	if (ret <= 0) {
		mail_index_unmap(&new_map);
		return ret < 0 ? -1 : (unusable ? 0 : 1);
	}
	i_assert(new_map->rec_map->records != NULL);

	index->last_read_log_file_seq = new_map->hdr.log_file_seq;
	index->last_read_log_file_tail_offset =
		new_map->hdr.log_file_tail_offset;

	mail_index_unmap(&index->map);
	index->map = new_map;
	*reason_r = "Index mapped";
	return 1;
}

int mail_index_map(struct mail_index *index,
		   enum mail_index_sync_handler_type type)
{
	const char *reason;
	int ret;

	i_assert(!index->mapping);

	index->mapping = TRUE;

	if (index->map == NULL)
		index->map = mail_index_map_alloc(index);

	/* first try updating the existing mapping from transaction log. */
	if (index->initial_mapped) {
		/* we're not creating/opening the index.
		   sync this as a view from transaction log. */
		ret = mail_index_sync_map(&index->map, type, FALSE, "initial mapping");
	} else {
		ret = 0;
	}

	if (ret == 0) {
		/* try to open and read the latest index. if it fails, we'll
		   fallback to updating the existing mapping from transaction
		   logs (which we'll also do even if the reopening succeeds).
		   if index files are unusable (e.g. major version change)
		   don't even try to use the transaction log. */
		ret = mail_index_map_latest_file(index, &reason);
		if (ret > 0) {
			/* if we're creating the index file, we don't have any
			   logs yet */
			if (index->log->head != NULL && index->indexid != 0) {
				/* and update the map with the latest changes
				   from transaction log */
				ret = mail_index_sync_map(&index->map, type,
							  TRUE, reason);
			}
			if (ret == 0) {
				/* we fsck'd the index. try opening again. */
				ret = mail_index_map_latest_file(index, &reason);
				if (ret > 0 && index->indexid != 0) {
					ret = mail_index_sync_map(&index->map,
						type, TRUE, reason);
				}
			}
		} else if (ret == 0 && !index->readonly) {
			/* make sure we don't try to open the file again */
			if (unlink(index->filepath) < 0 && errno != ENOENT)
				mail_index_set_syscall_error(index, "unlink()");
		}
	}

	if (ret >= 0)
		index->initial_mapped = TRUE;
	index->mapping = FALSE;
	return ret;
}
