/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "hex-dec.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "seq-range-array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "ostream-crlf.h"
#include "write-full.h"
#include "dbox-file.h"
#include "dbox-storage.h"
#include "dbox-uidlist.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>

#define DBOX_APPEND_MAX_OPEN_FDS 64

#define DBOX_UIDLIST_VERSION 1
#define DBOX_UIDLIST_FILENAME "index"

struct dbox_save_file {
        struct dbox_file *file;

	dev_t dev;
	ino_t ino;

	struct dotlock *dotlock;
	array_t ARRAY_DEFINE(seqs, unsigned int);

	/* append offset for the first mail we've saved */
	uoff_t append_offset;
};

struct dbox_uidlist {
	struct dbox_mailbox *mbox;
	char *path;
	int fd;

	struct dotlock *dotlock;
	int lock_fd;

	unsigned int version;
	uint32_t uid_validity, last_uid, last_file_seq;

	ino_t ino;
	time_t mtime;

	uint32_t file_seq_highwater;

	pool_t entry_pool;
	array_t ARRAY_DEFINE(entries, struct dbox_uidlist_entry *);
	uint32_t entry_last_file_seq;

	unsigned int appending:1;
	unsigned int need_full_rewrite:1;
};

struct dbox_uidlist_append_ctx {
	pool_t pool;
        struct dbox_uidlist *uidlist;

	unsigned int mail_count;

	array_t ARRAY_DEFINE(files, struct dbox_save_file *);
	unsigned int open_fds;

	unsigned int locked:1;
};

struct dbox_uidlist_sync_ctx {
	struct dbox_uidlist *uidlist;
	unsigned int modified:1;
};

const struct dotlock_settings uidlist_dotlock_settings = {
	NULL, NULL,

	60, 30, 120,

	NULL, NULL,
	FALSE
};

const struct dotlock_settings dbox_file_dotlock_set = {
	NULL, NULL,

	60, 30, 120,

	NULL, NULL,
	FALSE
};

struct dbox_uidlist *dbox_uidlist_init(struct dbox_mailbox *mbox)
{
	struct dbox_uidlist *uidlist;

	uidlist = i_new(struct dbox_uidlist, 1);
	uidlist->mbox = mbox;
	uidlist->fd = -1;
	uidlist->lock_fd = -1;
	uidlist->entry_pool =
		pool_alloconly_create("uidlist entry pool", 10240);
	uidlist->path =
		i_strconcat(mbox->path, "/"DBOX_MAILDIR_NAME"/"
			    DBOX_UIDLIST_FILENAME, NULL);
	ARRAY_CREATE(&uidlist->entries, default_pool,
		     struct dbox_uidlist_entry *, 64);
	return uidlist;
}

void dbox_uidlist_deinit(struct dbox_uidlist *uidlist)
{
	i_assert(!uidlist->appending);

	array_free(&uidlist->entries);
	pool_unref(uidlist->entry_pool);
	i_free(uidlist->path);
	i_free(uidlist);
}

static int uidlist_merge(array_t *uid_list, const struct seq_range *seqs)
{
	ARRAY_SET_TYPE(uid_list, struct seq_range);
	struct seq_range *range;
	unsigned int count;

	range = array_get_modifyable(uid_list, &count);
	i_assert(count > 0);

	if (seqs->seq1 <= range[count-1].seq2)
		return FALSE;

	if (seqs->seq1-1 == range[count-1].seq2) {
		/* we can just continue the existing range */
		range[count-1].seq2 = seqs->seq2;
	} else {
		array_append(uid_list, seqs, 1);
	}
	return TRUE;
}

static int dbox_uidlist_entry_cmp(const void *key, const void *p)
{
	const unsigned int *file_seq = key;
	struct dbox_uidlist_entry *const *entry = p;

	return (int)*file_seq - (int)(*entry)->file_seq;
}

static bool dbox_uidlist_add_entry(struct dbox_uidlist *uidlist,
				   const struct dbox_uidlist_entry *src_entry)
{
	struct dbox_uidlist_entry *dest_entry, **entries, **pos;
	const struct seq_range *range;
	unsigned int i, count;

	if (src_entry->file_seq > uidlist->entry_last_file_seq) {
		/* append new file sequence */
		dest_entry = p_new(uidlist->entry_pool,
				   struct dbox_uidlist_entry, 1);
		*dest_entry = *src_entry;
		array_append(&uidlist->entries, &dest_entry, 1);

		uidlist->entry_last_file_seq = src_entry->file_seq;
		if (src_entry->file_seq > uidlist->last_file_seq)
                        uidlist->last_file_seq = src_entry->file_seq;
	} else {
		/* merge to existing entry. they're written in order, so we
		   don't try to handle non-merging inserting. */
		entries = array_get_modifyable(&uidlist->entries, &count);
		pos = bsearch(&src_entry->file_seq, entries, count,
			      sizeof(*entries), dbox_uidlist_entry_cmp);
		if (pos == NULL) {
			mail_storage_set_critical(
				STORAGE(uidlist->mbox->storage),
				"%s: File sequences not ordered (%u < %u)",
				uidlist->path, src_entry->file_seq,
				uidlist->entry_last_file_seq);
			return FALSE;
		}

		/* now, do the merging. UIDs must be growing since only new
		   mails are appended */
		dest_entry = *pos;
		if (src_entry->create_time > dest_entry->create_time)
			dest_entry->create_time = src_entry->create_time;
		if (src_entry->file_size > dest_entry->file_size)
			dest_entry->file_size = src_entry->file_size;

		range = array_get(&src_entry->uid_list, &count);
		for (i = 0; i < count; i++) {
			if (!uidlist_merge(&dest_entry->uid_list, &range[i])) {
				mail_storage_set_critical(
					STORAGE(uidlist->mbox->storage),
					"%s: UIDs not ordered (file_seq=%u)",
					uidlist->path, src_entry->file_seq);
				return FALSE;
			}
		}
	}
	return TRUE;
}

static bool dbox_uidlist_next(struct dbox_uidlist *uidlist, const char *line)
{
	struct dbox_uidlist_entry *entry;
	struct seq_range range;
	uint32_t digit;
	int ret;

	/* <uid list> <file seq> [<last write timestamp> <file size>] */
	t_push();
	entry = t_new(struct dbox_uidlist_entry, 1);
	ARRAY_CREATE(&entry->uid_list, uidlist->entry_pool,
		     struct seq_range, 8);

	/* get uid list */
	range.seq1 = 0;
	for (digit = 0; *line != '\0'; line++) {
		if (*line >= '0' && *line <= '9')
			digit = digit * 10 + *line-'0';
		else {
			if (range.seq1 == 0)
				range.seq1 = digit;
			if (*line == ',' || *line == ' ') {
				if (range.seq1 > digit) {
					/* broken */
					array_clear(&entry->uid_list);
					break;
				}
				range.seq2 = digit;
				array_append(&entry->uid_list, &range, 1);

				if (digit > uidlist->last_uid) {
					/* last_uid isn't up to date */
					uidlist->last_uid = digit;
				}

				if (*line == ' ')
					break;
			}
			digit = 0;
		}
	}

	if (*line != ' ' || array_count(&entry->uid_list) == 0) {
		mail_storage_set_critical(STORAGE(uidlist->mbox->storage),
					  "%s: Corrupted entry", uidlist->path);
		t_pop();
		return FALSE;
	}

	/* get file seq */
	for (digit = 0, line++; *line >= '0' && *line <= '9'; line++)
		digit = digit * 10 + *line-'0';
	entry->file_seq = digit;

	/* get create timestamp */
	line++;
	for (; *line >= '0' && *line <= '9'; line++)
		entry->create_time = entry->create_time * 10 + *line-'0';

	if (*line != ' ') {
		mail_storage_set_critical(STORAGE(uidlist->mbox->storage),
					  "%s: Corrupted entry", uidlist->path);

		t_pop();
		return FALSE;
	}
	/* get file size */
	for (; *line >= '0' && *line <= '9'; line++)
		entry->file_size = entry->file_size * 10 + *line-'0';

	ret = dbox_uidlist_add_entry(uidlist, entry);
	t_pop();
	return ret;
}

static int dbox_uidlist_read(struct dbox_uidlist *uidlist)
{
	struct mail_storage *storage = STORAGE(uidlist->mbox->storage);
	const char *line;
	unsigned int uid_validity, last_uid, last_file_seq;
	struct istream *input;
	struct stat st;
	int ret;

	if (uidlist->fd != -1) {
		if (stat(uidlist->path, &st) < 0) {
			if (errno != ENOENT) {
				mail_storage_set_critical(storage,
					"stat(%s) failed: %m", uidlist->path);
				return -1;
			}
			return 0;
		}

		if (st.st_ino == uidlist->ino &&
		    st.st_mtime == uidlist->mtime) {
			/* unchanged */
			return 1;
		}
	}

	if (uidlist->fd != -1) {
		if (close(uidlist->fd) < 0)
			i_error("close(%s) failed: %m", uidlist->path);
	}

	uidlist->fd = open(uidlist->path, O_RDWR);
	if (uidlist->fd == -1) {
		if (errno == ENOENT)
			return 0;

		mail_storage_set_critical(storage,
			"open(%s) failed: %m", uidlist->path);
		return -1;
	}

	if (fstat(uidlist->fd, &st) < 0) {
		mail_storage_set_critical(storage,
			"fstat(%s) failed: %m", uidlist->path);
		return -1;
	}
	uidlist->ino = st.st_ino;
	uidlist->mtime = st.st_mtime;

	input = i_stream_create_file(uidlist->fd, default_pool, 65536, FALSE);

	/* read header: <version> <uidvalidity> <next-uid>.
	   Note that <next-uid> may be updated by UID lines, so it can't be
	   used directly. */
	line = i_stream_read_next_line(input);
	if (line == NULL || sscanf(line, "%u %u %u %u", &uidlist->version,
				   &uid_validity, &last_uid,
				   &last_file_seq) != 4 ||
	    uidlist->version != DBOX_UIDLIST_VERSION) {
                mail_storage_set_critical(storage,
			"Corrupted header in file %s (version = %u)",
			uidlist->path, uidlist->version);
		ret = 0;
	} else {
		uint32_t old_last_uid, old_last_file_seq;

		old_last_uid = uidlist->uid_validity == uid_validity ?
			uidlist->last_uid : 0;
		old_last_file_seq = uidlist->uid_validity == uid_validity ?
			uidlist->last_file_seq : 0;

		uidlist->uid_validity = uid_validity;
		uidlist->last_uid = last_uid;
		uidlist->last_file_seq = last_file_seq;
		uidlist->entry_last_file_seq = 0;
		p_clear(uidlist->entry_pool);
		array_clear(&uidlist->entries);

		ret = 1;
		while ((line = i_stream_read_next_line(input)) != NULL) {
			if (!dbox_uidlist_next(uidlist, line)) {
				ret = 0;
				break;
			}
		}

		if (ret > 0 && uidlist->last_uid < old_last_uid) {
			mail_storage_set_critical(storage,
				"%s: last_uid was lowered (%u -> %u)",
				uidlist->path, old_last_uid, uidlist->last_uid);
			ret = 0;
		}
		if (ret > 0 && uidlist->last_file_seq < old_last_file_seq) {
			mail_storage_set_critical(storage,
				"%s: last_uid was lowered (%u -> %u)",
				uidlist->path, old_last_file_seq,
				uidlist->last_file_seq);
			ret = 0;
		}

		if (uidlist->file_seq_highwater < uidlist->last_file_seq)
                        uidlist->file_seq_highwater = uidlist->last_file_seq;
	}

	if (ret == 0) {
		(void)unlink(uidlist->path);

		if (close(uidlist->fd) < 0)
			i_error("close(%s) failed: %m", uidlist->path);
		uidlist->fd = -1;
	}

	i_stream_unref(input);
	return ret;
}

static int dbox_uidlist_lock(struct dbox_uidlist *uidlist)
{
	i_assert(uidlist->lock_fd == -1);

	uidlist->lock_fd = file_dotlock_open(&uidlist_dotlock_settings,
					     uidlist->path, 0,
					     &uidlist->dotlock);
	if (uidlist->lock_fd == -1) {
		mail_storage_set_critical(STORAGE(uidlist->mbox->storage),
			"file_dotlock_open(%s) failed: %m", uidlist->path);
		return -1;
	}

	return 0;
}

static void dbox_uidlist_unlock(struct dbox_uidlist *uidlist)
{
	i_assert(uidlist->lock_fd != -1);

	(void)file_dotlock_delete(&uidlist->dotlock);
	uidlist->lock_fd = -1;
}

static struct dbox_uidlist_entry *
dbox_uidlist_entry_lookup_int(struct dbox_uidlist *uidlist, uint32_t file_seq,
			      unsigned int *idx_r)
{
	struct dbox_uidlist_entry *const *entries, **entry;
	unsigned int count;

	entries = array_get(&uidlist->entries, &count);
	entry = bsearch(&file_seq, entries, count, sizeof(*entries),
			dbox_uidlist_entry_cmp);
	if (entry == NULL)
		return NULL;

	*idx_r = entry - entries;
	return *entry;
}

struct dbox_uidlist_entry *
dbox_uidlist_entry_lookup(struct dbox_uidlist *uidlist, uint32_t file_seq)
{
	unsigned int idx;

	return dbox_uidlist_entry_lookup_int(uidlist, file_seq, &idx);
}

struct dbox_uidlist_append_ctx *
dbox_uidlist_append_init(struct dbox_uidlist *uidlist)
{
	struct dbox_uidlist_append_ctx *ctx;
	pool_t pool;

	i_assert(!uidlist->appending);

	pool = pool_alloconly_create("dbox uidlist append context", 4096);
	ctx = p_new(pool, struct dbox_uidlist_append_ctx, 1);
	ctx->pool = pool;
	ctx->uidlist = uidlist;
	ARRAY_CREATE(&ctx->files, pool, struct dbox_save_file *, 16);
	return ctx;
}

static int dbox_uidlist_full_rewrite(struct dbox_uidlist *uidlist)
{
	struct dbox_uidlist_entry *const *entries;
        struct ostream *output;
	struct stat st, st2;
	const char *lock_path;
	const struct seq_range *range;
	string_t *str;
	unsigned int i, count, ui, range_count;
	int ret = 0;

	i_assert(uidlist->lock_fd != -1);

	output = o_stream_create_file(uidlist->lock_fd, default_pool, 0, FALSE);

	t_push();
	str = t_str_new(256);

	/* header: <version> <uidvalidity> <next-uid>. */
	str_printfa(str, "%u %u %u %u\n", DBOX_UIDLIST_VERSION,
		    uidlist->uid_validity, uidlist->last_uid,
		    uidlist->last_file_seq);
	o_stream_send(output, str_data(str), str_len(str));

	entries = array_get(&uidlist->entries, &count);
	for (i = 0; i < count; i++) {
		str_truncate(str, 0);

		/* <uid list> <file seq> [<last write timestamp> <file size>] */
		range = array_get(&entries[i]->uid_list, &range_count);
		i_assert(range_count != 0);
		for (ui = 0; ui < range_count; ui++) {
			if (str_len(str) > 0)
				str_append_c(str, ',');
			if (range[ui].seq1 == range[ui].seq2)
				str_printfa(str, "%u", range[ui].seq1);
			else {
				str_printfa(str, "%u-%u",
					    range[ui].seq1, range[ui].seq2);
			}
		}
		str_printfa(str, " %u %s %"PRIuUOFF_T, entries[i]->file_seq,
			    dec2str(entries[i]->create_time),
			    entries[i]->file_size);
		str_append_c(str, '\n');
		if (o_stream_send(output, str_data(str), str_len(str)) < 0)
			break;
	}
	t_pop();

	if (output->stream_errno != 0) {
		mail_storage_set_critical(STORAGE(uidlist->mbox->storage),
			"write(%s) failed: %m", uidlist->path);
		ret = -1;
	}
	o_stream_unref(output);

	if (ret < 0)
		return -1;

	/* grow mtime by one if needed to make sure the last write is noticed */
	lock_path = file_dotlock_get_lock_path(uidlist->dotlock);
	if (stat(uidlist->path, &st) < 0) {
		if (errno != ENOENT) {
			mail_storage_set_critical(
				STORAGE(uidlist->mbox->storage),
				"stat(%s) failed: %m", uidlist->path);
			return -1;
		}
		st.st_mtime = 0;
	}
	if (fstat(uidlist->lock_fd, &st2) < 0) {
		mail_storage_set_critical(STORAGE(uidlist->mbox->storage),
					  "fstat(%s) failed: %m", lock_path);
		return -1;
	}

	if (st2.st_mtime <= st.st_mtime) {
		struct utimbuf ut;

		st2.st_mtime = ++st.st_mtime;
		ut.actime = ioloop_time;
		ut.modtime = st2.st_mtime;

		if (utime(lock_path, &ut) < 0) {
			mail_storage_set_critical(
				STORAGE(uidlist->mbox->storage),
				"utime(%s) failed: %m", lock_path);
			return -1;
		}
	}

	uidlist->ino = st2.st_ino;
	uidlist->mtime = st2.st_mtime;

	/* now, finish the uidlist update by renaming the lock file to
	   uidlist */
	uidlist->lock_fd = -1;
	if (file_dotlock_replace(&uidlist->dotlock, 0) < 0)
		return -1;

	uidlist->need_full_rewrite = FALSE;
	return 0;
}

static void dbox_uidlist_build_update_line(struct dbox_save_file *save_file,
					   string_t *str, uint32_t uid_start)
{
	const unsigned int *seqs;
	unsigned int seq, seq_count, start;

	str_truncate(str, 0);

	/* build uidlist string */
	seqs = array_get(&save_file->seqs, &seq_count);
	start = 0;
	for (seq = 0; seq < seq_count; seq++) {
		if (seq != seq_count-1) {
			if (seq == 0 || seqs[seq-1]+1 == seqs[seq])
				continue;
		}

		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_printfa(str, "%u", uid_start + seqs[start] - 1);
		if (seq != start)
			str_printfa(str, "-%u", uid_start + seqs[seq] - 1);
		start = seq + 1;
	}
	str_printfa(str, " %u", save_file->file->file_seq);

	/* add creation time and file size */
	str_printfa(str, " %s %s", dec2str(save_file->file->create_time),
		    dec2str(save_file->append_offset));
	str_append_c(str, '\n');
}

static void dbox_uidlist_update_changes(struct dbox_uidlist_append_ctx *ctx)
{
	struct dbox_save_file *const *files;
	string_t *str;
	unsigned int i, count;
	uint32_t uid_start;

	uid_start = ctx->uidlist->last_uid + 1;

	t_push();
	str = t_str_new(256);
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		dbox_uidlist_build_update_line(files[i], str, uid_start);
		if (!dbox_uidlist_next(ctx->uidlist, str_c(str)))
			i_panic("dbox_uidlist_next() internal update failed");
	}
	t_pop();
}

static int dbox_uidlist_append_changes(struct dbox_uidlist_append_ctx *ctx)
{
	struct dbox_save_file *const *files;
        struct ostream *output;
	struct utimbuf ut;
	struct stat st;
	unsigned int i, count;
	uint32_t uid_start;
	string_t *str;
	int ret = 0;

	i_assert(ctx->uidlist->fd != -1);

	if (lseek(ctx->uidlist->fd, 0, SEEK_END) < 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
			"lseek(%s) failed: %m", ctx->uidlist->path);
		return -1;
	}
	output = o_stream_create_file(ctx->uidlist->fd, default_pool, 0, FALSE);

	uid_start = ctx->uidlist->last_uid + 1;

	/* simply append the change-lines to the index file. if someone's
	   reading the file at the same time, it doesn't matter. the entries
	   are complete only after the LF has been written. */
	t_push();
	str = t_str_new(256);
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		dbox_uidlist_build_update_line(files[i], str, uid_start);
		if (!dbox_uidlist_next(ctx->uidlist, str_c(str)))
			i_panic("dbox_uidlist_next() internal update failed");
		o_stream_send(output, str_data(str), str_len(str));
	}
	t_pop();

	if (output->stream_errno != 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
			"write(%s) failed: %m", ctx->uidlist->path);
		ret = -1;
	}
	o_stream_unref(output);

	if (ret < 0)
		return -1;

	/* grow mtime by one to make sure the last write is noticed */
	if (fstat(ctx->uidlist->fd, &st) < 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
			"fstat(%s) failed: %m", ctx->uidlist->path);
		return -1;
	}

	ut.actime = ioloop_time;
	ut.modtime = st.st_mtime + 1;
	if (utime(ctx->uidlist->path, &ut) < 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
			"utime(%s) failed: %m", ctx->uidlist->path);
		return -1;
	}

	ctx->uidlist->ino = st.st_ino;
	ctx->uidlist->mtime = ut.modtime;
	return 0;
}

static int
dbox_uidlist_write_append_offsets(struct dbox_uidlist_append_ctx *ctx)
{
	struct dbox_save_file *const *files;
        struct dbox_file_header hdr;
	unsigned int i, count;
	int ret = 0;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		DEC2HEX(hdr.append_offset_hex,
			files[i]->file->output->offset);

		if (pwrite_full(files[i]->file->fd, hdr.append_offset_hex,
				sizeof(hdr.append_offset_hex),
				offsetof(struct dbox_file_header,
					 append_offset_hex)) < 0) {
			mail_storage_set_critical(
				STORAGE(ctx->uidlist->mbox->storage),
				"pwrite_full(%s) failed: %m",
				files[i]->file->path);
			ret = -1;
		}
	}
	return ret;
}

int dbox_uidlist_append_commit(struct dbox_uidlist_append_ctx *ctx)
{
	int ret;

	if (ctx->mail_count == 0) {
		/* nothing actually appended */
		dbox_uidlist_append_rollback(ctx);
		return 0;
	}

	i_assert(ctx->locked);

	if (dbox_uidlist_write_append_offsets(ctx) < 0)
		ret = -1;
	else {
		if (ctx->uidlist->need_full_rewrite) {
			dbox_uidlist_update_changes(ctx);
			ret = dbox_uidlist_full_rewrite(ctx->uidlist);
			if (ctx->uidlist->dotlock == NULL)
				ctx->locked = FALSE;
		} else {
			ret = dbox_uidlist_append_changes(ctx);
		}
	}

	dbox_uidlist_append_rollback(ctx);
	return ret;
}

void dbox_uidlist_append_rollback(struct dbox_uidlist_append_ctx *ctx)
{
	struct dbox_save_file *const *files;
	unsigned int i, count;

	/* unlock files */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++)
		file_dotlock_delete(&files[i]->dotlock);

	if (ctx->locked)
		dbox_uidlist_unlock(ctx->uidlist);
	ctx->uidlist->appending = FALSE;
	pool_unref(ctx->pool);
}

static int dbox_reopen_file(struct dbox_uidlist_append_ctx *ctx,
			    struct dbox_save_file *save_file)
{
	struct dbox_file *file = save_file->file;
	struct stat st;

	if (file->fd != -1)
		return 0;

	/* open the file and make sure it's the same as expected,
	   since we have it locked */
	file->fd = open(file->path, O_RDWR);
	if (file->fd == -1) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
					  "open(%s) failed: %m", file->path);
		return -1;
	}

	if (fstat(file->fd, &st) < 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
					  "fstat(%s) failed: %m", file->path);
		return -1;
	}

	if (st.st_ino != save_file->ino ||
	    !CMP_DEV_T(st.st_dev, save_file->dev)) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
			"Appended file changed unexpectedly: %s", file->path);
		return -1;
	}
	return 0;
}

static int dbox_file_write_header(struct dbox_mailbox *mbox,
				  struct dbox_file *file)
{
	struct dbox_file_header hdr;

	// FIXME: code duplication
	file->header_size = sizeof(hdr);
	file->append_offset = file->header_size;
	file->create_time = ioloop_time;
	file->mail_header_size = sizeof(struct dbox_mail_header);

	dbox_file_header_init(&hdr);
	if (o_stream_send(file->output, &hdr, sizeof(hdr)) < 0) {
		mail_storage_set_critical(STORAGE(mbox->storage),
			"write(%s) failed: %m", file->path);
		return -1;
	}
	return 0;
}

static int dbox_uidlist_files_lookup(struct dbox_uidlist_append_ctx *ctx,
				     uint32_t file_seq)
{
	struct dbox_save_file *const *files;
	unsigned int i, count;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file->file_seq == file_seq)
			return TRUE;
	}
	return FALSE;
}

static time_t get_min_timestamp(unsigned int days)
{
	struct tm tm;
	time_t stamp;

	if (days == 0)
		return 0;

	/* get beginning of today */
	tm = *localtime(&ioloop_time);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	stamp = mktime(&tm);
	if (stamp == (time_t)-1)
		i_panic("mktime(today) failed");

	return stamp - (3600*24 * (days-1));
}

#define DBOX_CAN_APPEND(mbox, create_time, file_size, min_usable_timestamp) \
	(((create_time) >= (min_usable_timestamp) && \
	  (file_size) < (mbox)->rotate_size) || \
	 (file_size) < (mbox)->rotate_min_size)

int dbox_uidlist_append_locked(struct dbox_uidlist_append_ctx *ctx,
			       struct dbox_file **file_r)
{
	struct dbox_mailbox *mbox = ctx->uidlist->mbox;
	struct dbox_save_file *const *files, *save_file;
	struct dbox_uidlist_entry *const *entries;
	struct dbox_file *file;
	struct dotlock *dotlock;
	struct ostream *output;
	string_t *str;
	unsigned int i, count;
	struct stat st;
	uint32_t file_seq;
	time_t min_usable_timestamp;
	int ret;

        min_usable_timestamp = get_min_timestamp(mbox->rotate_days);

	/* check first from already opened files */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (DBOX_CAN_APPEND(mbox, files[i]->file->create_time,
				    files[i]->append_offset,
				    min_usable_timestamp)) {
			if (dbox_reopen_file(ctx, files[i]) < 0)
				return -1;

			*file_r = file = files[i]->file;
			o_stream_seek(file->output, file->append_offset);
			return 0;
		}
	}

	/* check from other existing files. use uidlist's file_size field.
	   it's not completely trustworthy though. */
	str = str_new(ctx->pool, 64);
	entries = array_get(&ctx->uidlist->entries, &count);
	for (i = 0;; i++) {
                file_seq = 0; 
		for (; i < count; i++) {
			if (DBOX_CAN_APPEND(mbox, entries[i]->create_time,
					    entries[i]->file_size,
					    min_usable_timestamp) &&
			    !dbox_uidlist_files_lookup(ctx,
						       entries[i]->file_seq)) {
				file_seq = entries[i]->file_seq;
				break;
			}
		}

		if (file_seq == 0) {
			/* create new file */
			file_seq = dbox_uidlist_get_new_file_seq(ctx->uidlist);
		}

		/* try locking the file. */
		str_truncate(str, 0);
		str_printfa(str, "%s/"DBOX_MAILDIR_NAME"/"
			    DBOX_MAIL_FILE_PREFIX"%u", mbox->path, file_seq);
		ret = file_dotlock_create(&dbox_file_dotlock_set, str_c(str),
					  DOTLOCK_CREATE_FLAG_NONBLOCK,
					  &dotlock);
		if (ret > 0) {
			/* success */
			break;
		}
		if (ret < 0) {
			mail_storage_set_critical(STORAGE(mbox->storage),
				"file_dotlock_create(%s) failed: %m",
				str_c(str));
			return -1;
		}

		/* lock already exists, try next file */
	}

	save_file = p_new(ctx->pool, struct dbox_save_file, 1);
	save_file->file = file = p_new(ctx->pool, struct dbox_file, 1);
        save_file->dotlock = dotlock;
	file->file_seq = file_seq;
	file->path = str_free_without_data(str);

	file->fd = open(file->path, O_CREAT | O_RDWR, 0600);
	if (file->fd == -1) {
		mail_storage_set_critical(STORAGE(mbox->storage),
					  "open(%s) failed: %m", file->path);
		return -1;
	}

	if (fstat(file->fd, &st) < 0) {
		mail_storage_set_critical(STORAGE(mbox->storage),
					  "fstat(%s) failed: %m", file->path);
		(void)close(file->fd);
		return -1;
	}

	file->input = i_stream_create_file(file->fd, default_pool,
					   65536, FALSE);

	/* we'll be using CRLF linefeeds always */
	output = o_stream_create_file(file->fd, default_pool, 0, FALSE);
	file->output = o_stream_create_crlf(default_pool, output);
	o_stream_unref(output);

	if ((uoff_t)st.st_size < sizeof(struct dbox_file_header)) {
		if (dbox_file_write_header(mbox, file) < 0) {
			dbox_file_close(file);
			return -1;
		}
	} else {
		if (dbox_file_read_header(mbox, file) < 0) {
			dbox_file_close(file);
			return -1;
		}
		o_stream_seek(file->output, file->append_offset);
	}

	save_file->dev = st.st_dev;
	save_file->ino = st.st_ino;
	ARRAY_CREATE(&save_file->seqs, ctx->pool, unsigned int, 8);

	array_append(&ctx->files, &save_file, 1);
        *file_r = file;
	return 0;
}

void dbox_uidlist_append_finish_mail(struct dbox_uidlist_append_ctx *ctx,
				     struct dbox_file *file)
{
	struct dbox_save_file *const *files, *save_file = NULL;
	unsigned int i, count;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file == file) {
			save_file = files[i];
			break;
		}
	}
	i_assert(save_file != NULL);

	ctx->mail_count++;
	array_append(&save_file->seqs, &ctx->mail_count, 1);

	file->append_offset = file->output->offset;
}

struct dbox_file *
dbox_uidlist_append_lookup_file(struct dbox_uidlist_append_ctx *ctx,
				uint32_t file_seq)
{
	struct dbox_save_file *const *files;
	unsigned int i, count;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file->file_seq == file_seq)
			return files[i]->file;
	}

	i_unreached();
	return NULL;
}

uint32_t dbox_uidlist_get_new_file_seq(struct dbox_uidlist *uidlist)
{
	/* Note that unless uidlist is locked, it's not guaranteed that this
	   actually returns a new unused file sequence. */
	return ++uidlist->file_seq_highwater;
}

int dbox_uidlist_append_get_first_uid(struct dbox_uidlist_append_ctx *ctx,
				      uint32_t *uid_r)
{
	int ret;

	/* from now on we'll need to keep uidlist locked until it's
	   committed or rollbacked */
	if (!ctx->locked) {
		if (dbox_uidlist_lock(ctx->uidlist) < 0)
			return -1;
		ctx->locked = TRUE;

		/* update uidlist to make sure we have the latest state */
		if ((ret = dbox_uidlist_read(ctx->uidlist)) < 0)
			return -1;
		if (ret == 0) {
			/* file is deleted */
			ctx->uidlist->need_full_rewrite = TRUE;
		}
	}

	*uid_r = ctx->uidlist->last_uid + 1;
	return 0;
}

int dbox_uidlist_sync_init(struct dbox_uidlist *uidlist,
			   struct dbox_uidlist_sync_ctx **ctx_r,
			   time_t *mtime_r)
{
	int ret;

	*mtime_r = -1;
	if (dbox_uidlist_lock(uidlist) < 0)
		return -1;

	if ((ret = dbox_uidlist_read(uidlist)) < 0) {
		dbox_uidlist_unlock(uidlist);
		return -1;
	}

	if (ret == 0) {
		/* file is deleted */
		uidlist->need_full_rewrite = TRUE;
	} else {
		*mtime_r = uidlist->mtime;
	}

	*ctx_r = i_new(struct dbox_uidlist_sync_ctx, 1);
	(*ctx_r)->uidlist = uidlist;
	return 0;
}

int dbox_uidlist_sync_commit(struct dbox_uidlist_sync_ctx *ctx, time_t *mtime_r)
{
	int ret = 0;

	if (ctx->modified) {
		/* this call may or may not release the dotlock.. */
		ret = dbox_uidlist_full_rewrite(ctx->uidlist);
	}

	*mtime_r = ctx->uidlist->mtime;

	if (ctx->uidlist->dotlock != NULL)
		dbox_uidlist_unlock(ctx->uidlist);
	i_free(ctx);
	return ret;
}

void dbox_uidlist_sync_rollback(struct dbox_uidlist_sync_ctx *ctx)
{
	array_clear(&ctx->uidlist->entries);
	ctx->uidlist->ino = 0;
	ctx->uidlist->mtime = 0;

	dbox_uidlist_unlock(ctx->uidlist);
	i_free(ctx);
}

void dbox_uidlist_sync_from_scratch(struct dbox_uidlist_sync_ctx *ctx)
{
	array_clear(&ctx->uidlist->entries);
	ctx->uidlist->ino = 0;
	ctx->uidlist->mtime = 0;

	ctx->modified = TRUE;
	ctx->uidlist->need_full_rewrite = TRUE;
}

void dbox_uidlist_sync_set_modified(struct dbox_uidlist_sync_ctx *ctx)
{
	ctx->modified = TRUE;
}

void dbox_uidlist_sync_append(struct dbox_uidlist_sync_ctx *ctx,
			      const struct dbox_uidlist_entry *entry)
{
	struct dbox_uidlist_entry *const *entries, **pos;
	struct dbox_uidlist_entry *new_entry;
	unsigned int count;

	new_entry = p_new(ctx->uidlist->entry_pool,
			  struct dbox_uidlist_entry, 1);
	*new_entry = *entry;

	ARRAY_CREATE(&new_entry->uid_list, ctx->uidlist->entry_pool,
		     struct seq_range, array_count(&entry->uid_list) + 1);
	array_append_array(&new_entry->uid_list, &entry->uid_list);

	entries = array_get(&ctx->uidlist->entries, &count);
	if (count == 0 || entries[count-1]->file_seq < new_entry->file_seq)
		array_append(&ctx->uidlist->entries, &new_entry, 1);
	else {
		pos = bsearch_insert_pos(&new_entry->file_seq, entries,
					 count, sizeof(*entries),
					 dbox_uidlist_entry_cmp);
		array_insert(&ctx->uidlist->entries, pos - entries,
			     &new_entry, 1);
	}
}

int dbox_uidlist_sync_unlink(struct dbox_uidlist_sync_ctx *ctx,
			     uint32_t file_seq)
{
	struct dbox_uidlist_entry *entry;
	const char *path;
	unsigned int idx;

	entry = dbox_uidlist_entry_lookup_int(ctx->uidlist, file_seq, &idx);
	i_assert(entry != NULL);

	path = t_strdup_printf("%s/"DBOX_MAILDIR_NAME"/"
			       DBOX_MAIL_FILE_PREFIX"%u",
			       ctx->uidlist->mbox->path, entry->file_seq);
	if (unlink(path) < 0) {
		mail_storage_set_critical(STORAGE(ctx->uidlist->mbox->storage),
					  "unlink(%s) failed: %m", path);
		return -1;
	}
	array_delete(&ctx->uidlist->entries, idx, 1);

        dbox_uidlist_sync_set_modified(ctx);
	return 0;
}

uint32_t dbox_uidlist_sync_get_uid_validity(struct dbox_uidlist_sync_ctx *ctx)
{
	if (ctx->uidlist->uid_validity == 0) {
		ctx->uidlist->uid_validity = ioloop_time;
		ctx->modified = TRUE;
	}

	return ctx->uidlist->uid_validity;
}

uint32_t dbox_uidlist_sync_get_next_uid(struct dbox_uidlist_sync_ctx *ctx)
{
	return ctx->uidlist->last_uid + 1;
}

int dbox_uidlist_get_mtime(struct dbox_uidlist *uidlist, time_t *mtime_r)
{
	struct stat st;

	if (stat(uidlist->path, &st) < 0) {
		if (errno != ENOENT) {
			mail_storage_set_critical(
				STORAGE(uidlist->mbox->storage),
				"stat(%s) failed: %m", uidlist->path);
			return -1;
		}

		*mtime_r = 0;
	} else {
		*mtime_r = st.st_mtime;
	}
	return 0;
}
