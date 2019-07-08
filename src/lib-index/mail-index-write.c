/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

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
	i_assert((map->hdr.flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) == 0);
	i_assert(index->indexid != 0);

	fd = mail_index_create_tmp_file(index, index->filepath, &path);
	if (fd == -1)
		return -1;

	output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(output);

	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	o_stream_nsend(output, &map->hdr, base_size);
	o_stream_nsend(output, CONST_PTR_OFFSET(map->hdr_base, base_size),
		       map->hdr.header_size - base_size);
	o_stream_nsend(output, map->rec_map->records,
		       map->rec_map->records_count * map->hdr.record_size);
	if (o_stream_finish(output) < 0) {
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
		(void)mail_index_create_backup(index);

	if (ret == 0 && rename(path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     path, index->filepath);
		ret = -1;
	}

	if (ret < 0)
		i_unlink(path);
	return ret;
}

void mail_index_write(struct mail_index *index, bool want_rotate)
{
	struct mail_index_header *hdr = &index->map->hdr;

	i_assert(index->log_sync_locked);

	if (index->readonly)
		return;

	/* rotate the .log before writing index, so the index will point to
	   the latest log. */
	if (want_rotate &&
	    hdr->log_file_seq == index->log->head->hdr.file_seq &&
	    hdr->log_file_tail_offset == hdr->log_file_head_offset) {
		if (mail_transaction_log_rotate(index->log, FALSE) == 0) {
			struct mail_transaction_log_file *file =
				index->log->head;
			/* Log rotation refreshes the index, which may cause the
			   map to change. Because we're locked, it's not
			   supposed to happen and will likely lead to an
			   assert-crash below, but we still need to make sure
			   we're using the latest map to do the checks. */
			hdr = &index->map->hdr;
			i_assert(file->hdr.prev_file_seq == hdr->log_file_seq);
			i_assert(file->hdr.prev_file_offset == hdr->log_file_head_offset);
			hdr->log_file_seq = file->hdr.file_seq;
			hdr->log_file_head_offset =
				hdr->log_file_tail_offset = file->hdr.hdr_size;
			/* Assume .log.2 was created successfully. If it
			   wasn't, it just causes an extra stat() and gets
			   fixed later on. */
			hdr->log2_rotate_time = ioloop_time;
		}
	}

	if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
		if (mail_index_recreate(index) < 0) {
			(void)mail_index_move_to_memory(index);
			return;
		}
	}

	index->last_read_log_file_seq = hdr->log_file_seq;
	index->last_read_log_file_tail_offset = hdr->log_file_tail_offset;
}
