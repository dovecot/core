/* Copyright (C) 2003-2007 Timo Sirainen */

#include "lib.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#include <stdio.h>

static int mail_index_recreate(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;
	const char *path;
	int ret, fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	fd = mail_index_create_tmp_file(index, &path);
	if (fd == -1)
		return -1;

	/* write base header */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	ret = write_full(fd, &map->hdr, base_size);
	if (ret == 0) {
		/* write extended headers */
		ret = write_full(fd, CONST_PTR_OFFSET(map->hdr_base, base_size),
				 map->hdr.header_size - base_size);
	}
	if (ret == 0) {
		ret = write_full(fd, map->records, map->records_count *
				 map->hdr.record_size);
	}
	if (ret < 0)
		mail_index_file_set_syscall_error(index, path, "write_full()");

	if (ret == 0 && !index->fsync_disable && fsync(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "fsync()");
		ret = -1;
	}

	if (close(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "close()");
		ret = -1;
	}

	if (ret == 0 && rename(path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     path, index->filepath);
		ret = -1;
	}

	if (ret < 0) {
		if (unlink(path) < 0) {
			mail_index_set_error(index, "unlink(%s) failed: %m",
					     path);
		}
	}
	return ret;
}

static int mail_index_write_map_over(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	/* write records. */
	if (map->write_seq_first != 0) {
		size_t rec_offset =
			(map->write_seq_first-1) * map->hdr.record_size;

		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->records, rec_offset),
				(map->write_seq_last -
				 map->write_seq_first + 1) *
				map->hdr.record_size,
				map->hdr.header_size + rec_offset) < 0)
			return -1;
	}

	/* write base header. it has changed practically always, so
	   map->write_base_header might not be TRUE here in all situations.
	   It's used only to figure out if we want to write the map at all. */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	if (pwrite_full(index->fd, &map->hdr, base_size, 0) < 0)
		return -1;

	/* write extended headers */
	if (map->write_ext_header) {
		base_size = map->hdr.base_header_size;
		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->hdr_base, base_size),
				map->hdr.header_size - base_size,
				base_size) < 0)
			return -1;
	}
	return 0;
}

#define mail_index_map_has_changed(map) \
	((map)->write_base_header || (map)->write_ext_header || \
	 (map)->write_seq_first != 0)

void mail_index_write(struct mail_index *index, bool want_rotate)
{
	struct mail_index_map *map = index->map;
	const struct mail_index_header *hdr = &map->hdr;
	unsigned int lock_id;

	if (!mail_index_map_has_changed(map))
		return;

	if (hdr->base_header_size < sizeof(*hdr)) {
		/* header size growed. we can't update this file anymore. */
		map->write_atomic = TRUE;
	}
	if (index->fd == -1) {
		/* index file doesn't exist, it's corrupted or we haven't
		   opened it for some reason */
		map->write_atomic = TRUE;
	}
	if (!map->write_atomic) {
		if (mail_index_try_lock_exclusive(index, &lock_id) <= 0) {
			/* locking failed, rewrite */
			map->write_atomic = TRUE;
		}
	}

	if (map->write_atomic) {
		if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
			if (mail_index_recreate(index) < 0) {
				mail_index_move_to_memory(index);
				return;
			}
		}
	} else {
		if (mail_index_write_map_over(index) < 0) {
			mail_index_set_error(index,
				"pwrite_full(%s) failed: %m", index->filepath);
			mail_index_set_inconsistent(index);
		}
		mail_index_unlock(index, lock_id);
	}

	index->last_read_log_file_tail_offset = hdr->log_file_tail_offset;

	map->write_atomic = FALSE;
	map->write_seq_first = map->write_seq_last = 0;
	map->write_base_header = FALSE;
	map->write_ext_header = FALSE;

	if (want_rotate &&
	    hdr->log_file_seq == index->log->head->hdr.file_seq &&
	    hdr->log_file_tail_offset == hdr->log_file_head_offset)
		(void)mail_transaction_log_rotate(index->log);
}
