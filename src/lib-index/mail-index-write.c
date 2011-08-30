/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "read-full.h"
#include "write-full.h"
#include "ostream.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#include <stdio.h>

#define MAIL_INDEX_MIN_UPDATE_SIZE 1024
/* if we're updating >= count-n messages, recreate the index */
#define MAIL_INDEX_MAX_OVERWRITE_NEG_SEQ_COUNT 10

static int mail_index_create_backup(struct mail_index *index)
{
	const char *backup_path, *tmp_backup_path;
	int ret;

	if (index->fd != -1) {
		/* we very much want to avoid creating a backup file that
		   hasn't been written to disk yet */
		if (fdatasync(index->fd) < 0) {
			mail_index_set_error(index, "fdatasync(%s) failed: %m",
					     index->filepath);
			return -1;
		}
	}

	backup_path = t_strconcat(index->filepath, ".backup", NULL);
	tmp_backup_path = t_strconcat(backup_path, ".tmp", NULL);
	ret = link(index->filepath, tmp_backup_path);
	if (ret < 0 && errno == EEXIST) {
		if (unlink(tmp_backup_path) < 0 && errno != ENOENT) {
			mail_index_set_error(index, "unlink(%s) failed: %m",
					     tmp_backup_path);
			return -1;
		}
		ret = link(index->filepath, tmp_backup_path);
	}
	if (ret < 0) {
		if (errno == ENOENT) {
			/* no dovecot.index file, ignore */
			return 0;
		}
		mail_index_set_error(index, "link(%s, %s) failed: %m",
				     index->filepath, tmp_backup_path);
		return -1;
	}

	if (rename(tmp_backup_path, backup_path) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     tmp_backup_path, backup_path);
		return -1;
	}
	return 0;
}

static int mail_index_recreate(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	struct ostream *output;
	unsigned int base_size;
	const char *path;
	int ret = 0, fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));
	i_assert(map->hdr.indexid == index->indexid);

	fd = mail_index_create_tmp_file(index, &path);
	if (fd == -1)
		return -1;

	output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(output);

	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	if (o_stream_send(output, &map->hdr, base_size) < 0 ||
	    o_stream_send(output, CONST_PTR_OFFSET(map->hdr_base, base_size),
			  map->hdr.header_size - base_size) < 0 ||
	    o_stream_send(output, map->rec_map->records,
			  map->rec_map->records_count *
			  map->hdr.record_size) < 0 ||
	    o_stream_flush(output) < 0) {
		mail_index_file_set_syscall_error(index, path, "write()");
		ret = -1;
	}
	o_stream_destroy(&output);

	if (ret == 0 && index->fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(fd) < 0) {
			mail_index_file_set_syscall_error(index, path,
							  "fdatasync()");
			ret = -1;
		}
	}

	if (close(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "close()");
		ret = -1;
	}

	if ((index->flags & MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS) != 0)
		mail_index_create_backup(index);

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
	struct mail_index_record_map *rec_map = map->rec_map;
	unsigned int base_size;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	/* write extended headers */
	if (map->write_ext_header) {
		base_size = map->hdr.base_header_size;
		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->hdr_base, base_size),
				map->hdr.header_size - base_size,
				base_size) < 0)
			return -1;
	}

	/* write records. */
	if (rec_map->write_seq_first != 0) {
		size_t rec_offset =
			(rec_map->write_seq_first-1) * map->hdr.record_size;
		size_t recs_size = map->hdr.record_size *
			(rec_map->write_seq_last -
			 rec_map->write_seq_first + 1);

		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(rec_map->records, rec_offset),
				recs_size,
				map->hdr.header_size + rec_offset) < 0)
			return -1;
	}

	/* Write base header last. If we happen to crash in above pwrites, it
	   doesn't matter because we haven't yet written log file offsets, so
	   all the changes will be re-applied and the header/data state will
	   stay valid.

	   The base header changes practically always, so
	   map->write_base_header might not be TRUE here in all situations.
	   It's used only to figure out if we want to write the map at all. */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	if (pwrite_full(index->fd, &map->hdr, base_size, 0) < 0)
		return -1;
	return 0;
}

static bool mail_index_has_last_changed(struct mail_index *index)
{
	struct mail_index_header hdr;
	int ret;

	if ((ret = pread_full(index->fd, &hdr, sizeof(hdr), 0)) <= 0) {
		if (ret < 0 && errno != ESTALE)
			mail_index_set_syscall_error(index, "pread_full()");
		return TRUE;
	}

	return hdr.log_file_head_offset !=
		index->last_read_log_file_head_offset ||
		hdr.log_file_seq != index->last_read_log_file_seq;
}

#define mail_index_map_has_changed(map) \
	((map)->write_base_header || (map)->write_ext_header || \
	 (map)->rec_map->write_seq_first != 0)

void mail_index_write(struct mail_index *index, bool want_rotate)
{
	struct mail_index_map *map = index->map;
	const struct mail_index_header *hdr = &map->hdr;
	struct stat st;
	unsigned int lock_id;
	int ret;

	i_assert(index->log_sync_locked);

	if (!mail_index_map_has_changed(map) || index->readonly)
		return;

	if (hdr->base_header_size < sizeof(*hdr)) {
		/* header size growed. we can't update this file anymore. */
		map->write_atomic = TRUE;
	}
	if (index->fd == -1 || index->last_read_log_file_seq == 0) {
		/* index file doesn't exist, it's corrupted or we haven't
		   opened it for some reason */
		map->write_atomic = TRUE;
	}

	if (index->last_read_stat.st_size < MAIL_INDEX_MIN_UPDATE_SIZE ||
	    (map->rec_map->write_seq_last - map->rec_map->write_seq_first + 1) +
	    MAIL_INDEX_MAX_OVERWRITE_NEG_SEQ_COUNT >=
	    map->rec_map->records_count) {
		/* the file is so small that we don't even bother trying to
		   update it / changes are so large we might as well recreate */
		map->write_atomic = TRUE;
	}

	if (!map->write_atomic) {
		/* we can't update the file unless it's the same as it was
		   when we last read it. this is the first quick check before
		   locking. */
		if (stat(index->filepath, &st) < 0) {
			if (errno != ENOENT)
				mail_index_set_syscall_error(index, "stat()");
			map->write_atomic = TRUE;
		} else if (st.st_ino != index->last_read_stat.st_ino ||
			   !CMP_ST_CTIME(&st, &index->last_read_stat))
			map->write_atomic = TRUE;
	}

	if (!map->write_atomic) {
		if (mail_index_try_lock_exclusive(index, &lock_id) <= 0) {
			/* locking failed, recreate */
			map->write_atomic = TRUE;
		} else if (mail_index_has_last_changed(index)) {
			/* changed, we can't trust updating it anymore */
			map->write_atomic = TRUE;
			mail_index_unlock(index, &lock_id);
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
		ret = mail_index_write_map_over(index);
		if (ret < 0)
			mail_index_set_syscall_error(index, "pwrite_full()");
		else if (index->fsync_mode == FSYNC_MODE_ALWAYS) {
			ret = fdatasync(index->fd);
			if (ret < 0) {
				mail_index_set_syscall_error(index,
							     "fdatasync()");
			}
		}
		mail_index_unlock(index, &lock_id);

		if (ret < 0) {
			/* hopefully didn't break badly */
			mail_index_move_to_memory(index);
			return;
		}
	}

	index->last_read_log_file_seq = hdr->log_file_seq;
	index->last_read_log_file_head_offset = hdr->log_file_head_offset;
	index->last_read_log_file_tail_offset = hdr->log_file_tail_offset;

	map->rec_map->write_seq_first = map->rec_map->write_seq_last = 0;
	map->write_atomic = FALSE;
	map->write_base_header = FALSE;
	map->write_ext_header = FALSE;

	if (want_rotate &&
	    hdr->log_file_seq == index->log->head->hdr.file_seq &&
	    hdr->log_file_tail_offset == hdr->log_file_head_offset)
		(void)mail_transaction_log_rotate(index->log, FALSE);
}
