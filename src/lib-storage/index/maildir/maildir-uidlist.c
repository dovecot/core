/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "istream.h"
#include "str.h"
#include "file-dotlock.h"
#include "write-full.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <utime.h>

/* how many seconds to wait before overriding uidlist.lock */
#define UIDLIST_LOCK_STALE_TIMEOUT (60*5)

#define UIDLIST_IS_LOCKED(uidlist) \
	((uidlist)->lock_fd != -1)

struct maildir_uidlist_rec {
	uint32_t uid;
	uint32_t flags;
	char *filename;
};

struct maildir_uidlist {
	struct index_mailbox *ibox;
	char *fname;
	int lock_fd;

	time_t last_mtime;

	pool_t record_pool;
	buffer_t *record_buf;
	struct hash_table *files;

	unsigned int version;
	unsigned int uid_validity, next_uid, last_read_uid;
	uint32_t first_recent_uid;

	unsigned int initial_read:1;
	unsigned int initial_sync:1;
};

struct maildir_uidlist_sync_ctx {
	struct maildir_uidlist *uidlist;

	pool_t record_pool;
	buffer_t *record_buf;
	struct hash_table *files;

	unsigned int first_new_pos;
	unsigned int new_files_count;

	unsigned int partial:1;
	unsigned int synced:1;
	unsigned int locked:1;
	unsigned int finished:1;
	unsigned int failed:1;
};

struct maildir_uidlist_iter_ctx {
	const struct maildir_uidlist_rec *const *next, *const *end;
};

int maildir_uidlist_try_lock(struct maildir_uidlist *uidlist)
{
	const char *path;
	mode_t old_mask;
	int fd;

	if (UIDLIST_IS_LOCKED(uidlist))
		return 1;

	path = t_strconcat(uidlist->ibox->control_dir,
			   "/" MAILDIR_UIDLIST_NAME, NULL);
        old_mask = umask(0777 & ~uidlist->ibox->mail_create_mode);
	fd = file_dotlock_open(path, uidlist->ibox->storage->temp_prefix,
			       NULL, 0, 0, UIDLIST_LOCK_STALE_TIMEOUT,
			       NULL, NULL);
	umask(old_mask);
	if (fd == -1) {
		if (errno == EAGAIN)
			return 0;
		mail_storage_set_critical(uidlist->ibox->box.storage,
			"file_dotlock_open(%s) failed: %m", path);
		return -1;
	}

	uidlist->lock_fd = fd;
	return 1;
}

void maildir_uidlist_unlock(struct maildir_uidlist *uidlist)
{
	const char *path;

	if (!UIDLIST_IS_LOCKED(uidlist))
		return;

	path = t_strconcat(uidlist->ibox->control_dir,
			   "/" MAILDIR_UIDLIST_NAME, NULL);
	(void)file_dotlock_delete(path, NULL, uidlist->lock_fd);
	uidlist->lock_fd = -1;
}

struct maildir_uidlist *maildir_uidlist_init(struct index_mailbox *ibox)
{
	struct maildir_uidlist *uidlist;

	uidlist = i_new(struct maildir_uidlist, 1);
	uidlist->ibox = ibox;
	uidlist->fname =
		i_strconcat(ibox->control_dir, "/" MAILDIR_UIDLIST_NAME, NULL);
	uidlist->lock_fd = -1;
	uidlist->record_buf =
		buffer_create_dynamic(default_pool, 512, (size_t)-1);
	uidlist->files = hash_create(default_pool, default_pool, 4096,
				     maildir_hash, maildir_cmp);

	uidlist->next_uid = 1;

	return uidlist;
}

void maildir_uidlist_deinit(struct maildir_uidlist *uidlist)
{
	i_assert(!UIDLIST_IS_LOCKED(uidlist));

	hash_destroy(uidlist->files);
	if (uidlist->record_pool != NULL)
		pool_unref(uidlist->record_pool);

	buffer_free(uidlist->record_buf);
	i_free(uidlist->fname);
	i_free(uidlist);
}

static void
maildir_uidlist_mark_recent(struct maildir_uidlist *uidlist, uint32_t uid)
{
	if (uidlist->first_recent_uid == 0 ||
	    uid < uidlist->first_recent_uid)
		uidlist->first_recent_uid = uid;
}

static int maildir_uidlist_next(struct maildir_uidlist *uidlist,
				const char *line, uint32_t last_uid)
{
        struct maildir_uidlist_rec *rec;
	uint32_t uid, flags;

	uid = flags = 0;
	while (*line >= '0' && *line <= '9') {
		uid = uid*10 + (*line - '0');
		line++;
	}

	if (uid <= last_uid) {
		/* we already have this */
		return 1;
	}

	if (uid == 0 || *line != ' ') {
		/* invalid file */
                mail_storage_set_critical(uidlist->ibox->box.storage,
			"Invalid data in file %s", uidlist->fname);
		return 0;
	}
	if (uid <= uidlist->last_read_uid) {
                mail_storage_set_critical(uidlist->ibox->box.storage,
			"UIDs not ordered in file %s (%u > %u)",
			uidlist->fname, uid, uidlist->last_read_uid);
		return 0;
	}
	uidlist->last_read_uid = uid;

	if (uid >= uidlist->next_uid) {
                mail_storage_set_critical(uidlist->ibox->box.storage,
			"UID larger than next_uid in file %s (%u >= %u)",
			uidlist->fname, uid, uidlist->next_uid);
		return 0;
	}

	while (*line == ' ') line++;

	flags = 0;
	if (uidlist->version > 1) {
		while (*line != ' ') {
			switch (*line) {
			case 'N':
				flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
				break;
			}
			line++;
		}
		while (*line == ' ') line++;
	} else {
		/* old version, have to assume it's in new dir since we
		   don't know */
		flags |= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
	}

	if (hash_lookup_full(uidlist->files, line, NULL, NULL)) {
                mail_storage_set_critical(uidlist->ibox->box.storage,
			"Duplicate file in uidlist file %s: %s",
			uidlist->fname, line);
		return 0;
	}

	rec = p_new(uidlist->record_pool, struct maildir_uidlist_rec, 1);
	rec->uid = uid;
	rec->flags = flags | MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	rec->filename = p_strdup(uidlist->record_pool, line);
	hash_insert(uidlist->files, rec->filename, rec);
	buffer_append(uidlist->record_buf, &rec, sizeof(rec));
	return 1;
}

int maildir_uidlist_update(struct maildir_uidlist *uidlist)
{
	struct mail_storage *storage = uidlist->ibox->box.storage;
	const struct maildir_uidlist_rec *const *rec_p;
	const char *line;
	unsigned int uid_validity, next_uid;
	struct istream *input;
	struct stat st;
	uint32_t last_uid;
	size_t size;
	int fd, ret;

	if (uidlist->last_mtime != 0) {
		if (stat(uidlist->fname, &st) < 0) {
			if (errno != ENOENT) {
				mail_storage_set_critical(storage,
					"stat(%s) failed: %m", uidlist->fname);
				return -1;
			}
			return 0;
		}

		if (st.st_mtime == uidlist->last_mtime) {
			/* unchanged */
			return 1;
		}
	}

	fd = open(uidlist->fname, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
				"open(%s) failed: %m", uidlist->fname);
			return -1;
		}
		uidlist->initial_read = TRUE;
		return 0;
	}

	if (fstat(fd, &st) < 0) {
		mail_storage_set_critical(storage,
			"fstat(%s) failed: %m", uidlist->fname);
		return -1;
	}

	if (uidlist->record_pool == NULL) {
		uidlist->record_pool =
			pool_alloconly_create("uidlist record_pool",
					      nearest_power(st.st_size -
							    st.st_size/8));
	}

	rec_p = buffer_get_data(uidlist->record_buf, &size);
	last_uid = size == 0 ? 0 : rec_p[(size / sizeof(*rec_p))-1]->uid;

	uidlist->version = 0;

	input = i_stream_create_file(fd, default_pool, 4096, TRUE);

	/* get header */
	line = i_stream_read_next_line(input);
	if (line == NULL || sscanf(line, "%u %u %u", &uidlist->version,
				   &uid_validity, &next_uid) != 3 ||
	    uidlist->version < 1 || uidlist->version > 2) {
		/* broken file */
                mail_storage_set_critical(storage,
			"Corrupted header in file %s (version = %u)",
			uidlist->fname, uidlist->version);
		ret = 0;
	} else if (uid_validity == uidlist->uid_validity &&
		   next_uid < uidlist->next_uid) {
                mail_storage_set_critical(storage,
			"%s: next_uid was lowered (%u -> %u)",
			uidlist->fname, uidlist->next_uid, next_uid);
		ret = 0;
	} else {
		uidlist->uid_validity = uid_validity;
		uidlist->next_uid = next_uid;

		ret = 1;
		while ((line = i_stream_read_next_line(input)) != NULL) {
			if (!maildir_uidlist_next(uidlist, line, last_uid)) {
				ret = 0;
				break;
			}
		}
	}

	if (ret != 0)
		uidlist->last_mtime = st.st_mtime;
	else {
		(void)unlink(uidlist->fname);
                uidlist->last_mtime = 0;
	}

	i_stream_unref(input);
	uidlist->initial_read = TRUE;
	return ret;
}

static const struct maildir_uidlist_rec *
maildir_uidlist_lookup_rec(struct maildir_uidlist *uidlist, uint32_t uid,
			   unsigned int *idx_r)
{
	const struct maildir_uidlist_rec *const *rec_p;
	unsigned int idx, left_idx, right_idx;
	size_t size;

	if (!uidlist->initial_read) {
		/* first time we need to read uidlist */
		if (maildir_uidlist_update(uidlist) < 0)
			return NULL;
	}

	rec_p = buffer_get_data(uidlist->record_buf, &size);
	size /= sizeof(*rec_p);

	idx = 0;
	left_idx = 0;
	right_idx = size;

	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (rec_p[idx]->uid < uid)
			left_idx = idx+1;
		else if (rec_p[idx]->uid > uid)
			right_idx = idx;
		else {
			*idx_r = idx;
			return rec_p[idx];
		}
	}

	if (idx > 0) idx--;
	*idx_r = idx;
	return NULL;
}

const char *
maildir_uidlist_lookup(struct maildir_uidlist *uidlist, uint32_t uid,
		       enum maildir_uidlist_rec_flag *flags_r)
{
	const struct maildir_uidlist_rec *rec;
	unsigned int idx;

	rec = maildir_uidlist_lookup_rec(uidlist, uid, &idx);
	if (rec == NULL)
		return NULL;

	*flags_r = rec->flags;
	return rec->filename;
}

int maildir_uidlist_is_recent(struct maildir_uidlist *uidlist, uint32_t uid)
{
	enum maildir_uidlist_rec_flag flags;

	if (uidlist->first_recent_uid == 0 || uid < uidlist->first_recent_uid)
		return FALSE;

	if (maildir_uidlist_lookup(uidlist, uid, &flags) == NULL)
		return FALSE;

	i_assert(uidlist->first_recent_uid != uid ||
		 (flags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0);
	return (flags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0;
}

uint32_t maildir_uidlist_get_recent_count(struct maildir_uidlist *uidlist)
{
	const struct maildir_uidlist_rec *const *rec_p;
	unsigned int idx;
	size_t size;
	uint32_t count;

	if (!uidlist->initial_sync) {
		/* we haven't synced yet, trust index */
		const struct mail_index_header *hdr;

		if (mail_index_get_header(uidlist->ibox->view, &hdr) < 0)
			return 0;
		return hdr->recent_messages_count;
	}

	/* all recent messages were in new/ dir, so even if we did only
	   a partial sync we should know all the recent messages. */

	if (uidlist->first_recent_uid == 0)
		return 0;

	rec_p = buffer_get_data(uidlist->record_buf, &size);
	size /= sizeof(*rec_p);

	maildir_uidlist_lookup_rec(uidlist, uidlist->first_recent_uid, &idx);
	for (count = 0; idx < size; idx++) {
		if ((rec_p[idx]->flags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0)
			count++;
	}
	return count;
}

uint32_t maildir_uidlist_get_uid_validity(struct maildir_uidlist *uidlist)
{
	return uidlist->uid_validity;
}

void maildir_uidlist_set_uid_validity(struct maildir_uidlist *uidlist,
				      uint32_t uid_validity)
{
	uidlist->uid_validity = uid_validity;
}

uint32_t maildir_uidlist_get_next_uid(struct maildir_uidlist *uidlist)
{
	return !uidlist->initial_read ? 0 : uidlist->next_uid;
}

static int maildir_uidlist_rewrite_fd(struct maildir_uidlist *uidlist,
				      const char *temp_path)
{
	struct mail_storage *storage = uidlist->ibox->box.storage;
	struct maildir_uidlist_iter_ctx *iter;
	struct utimbuf ut;
	string_t *str;
	uint32_t uid;
        enum maildir_uidlist_rec_flag flags;
	const char *filename, *flags_str;
	int ret = 0;

	uidlist->version = 2;

	if (uidlist->uid_validity == 0)
		uidlist->uid_validity = ioloop_time;

	str = t_str_new(4096);
	str_printfa(str, "%u %u %u\n", uidlist->version,
		    uidlist->uid_validity, uidlist->next_uid);

	iter = maildir_uidlist_iter_init(uidlist->ibox->uidlist);
	while (maildir_uidlist_iter_next(iter, &uid, &flags, &filename)) {
		if (str_len(str) + MAX_INT_STRLEN +
		    strlen(filename) + 2 >= 4096) {
			/* flush buffer */
			if (write_full(uidlist->lock_fd,
				       str_data(str), str_len(str)) < 0) {
				mail_storage_set_critical(storage,
					"write_full(%s) failed: %m", temp_path);
				ret = -1;
				break;
			}
			str_truncate(str, 0);
		}

		flags_str = (flags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0 ?
			"N" : "-";
		str_printfa(str, "%u %s %s\n", uid, flags_str, filename);
	}
	maildir_uidlist_iter_deinit(iter);

	if (ret < 0)
		return -1;

	if (write_full(uidlist->lock_fd, str_data(str), str_len(str)) < 0) {
		mail_storage_set_critical(storage,
			"write_full(%s) failed: %m", temp_path);
		return -1;
	}

	/* uidlist's mtime must grow every time */
	uidlist->last_mtime = ioloop_time <= uidlist->last_mtime ?
		uidlist->last_mtime + 1 : ioloop_time;
	ut.actime = ioloop_time;
	ut.modtime = uidlist->last_mtime;
	if (utime(temp_path, &ut) < 0) {
		mail_storage_set_critical(storage,
			"utime(%s) failed: %m", temp_path);
		return -1;
	}

	if (fsync(uidlist->lock_fd) < 0) {
		mail_storage_set_critical(storage,
			"fsync(%s) failed: %m", temp_path);
		return -1;
	}

	return 0;
}

static int maildir_uidlist_rewrite(struct maildir_uidlist *uidlist)
{
	struct index_mailbox *ibox = uidlist->ibox;
	const char *temp_path, *db_path;
	int ret;

	i_assert(UIDLIST_IS_LOCKED(uidlist));

	temp_path = t_strconcat(ibox->control_dir,
				"/" MAILDIR_UIDLIST_NAME ".lock", NULL);
	ret = maildir_uidlist_rewrite_fd(uidlist, temp_path);

	if (ret == 0) {
		db_path = t_strconcat(ibox->control_dir,
				      "/" MAILDIR_UIDLIST_NAME, NULL);

		if (file_dotlock_replace(db_path, NULL, uidlist->lock_fd,
					 FALSE) <= 0) {
			mail_storage_set_critical(ibox->box.storage,
				"file_dotlock_replace(%s) failed: %m", db_path);
			(void)unlink(temp_path);
			ret = -1;
		}
		uidlist->lock_fd = -1;
	} else {
                maildir_uidlist_unlock(uidlist);
	}

	return ret;
}

static void maildir_uidlist_mark_all(struct maildir_uidlist *uidlist,
				     int nonsynced)
{
	struct maildir_uidlist_rec **rec_p;
	size_t i, size;

	rec_p = buffer_get_modifyable_data(uidlist->record_buf, &size);
	size /= sizeof(*rec_p);

	if (nonsynced) {
		for (i = 0; i < size; i++)
			rec_p[i]->flags |= MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	} else {
		for (i = 0; i < size; i++)
			rec_p[i]->flags &= ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	}
}

struct maildir_uidlist_sync_ctx *
maildir_uidlist_sync_init(struct maildir_uidlist *uidlist, int partial)
{
	struct maildir_uidlist_sync_ctx *ctx;
	size_t size;

	ctx = i_new(struct maildir_uidlist_sync_ctx, 1);
	ctx->uidlist = uidlist;
	ctx->partial = partial;

	if (partial) {
		/* initially mark all nonsynced */
                maildir_uidlist_mark_all(uidlist, TRUE);
		return ctx;
	}

	ctx->record_pool =
		pool_alloconly_create("maildir_uidlist_sync", 16384);
	ctx->files = hash_create(default_pool, ctx->record_pool, 4096,
				 maildir_hash, maildir_cmp);

	size = buffer_get_used_size(uidlist->record_buf);
	ctx->record_buf = buffer_create_dynamic(default_pool, size, (size_t)-1);
	return ctx;
}

static int maildir_uidlist_sync_uidlist(struct maildir_uidlist_sync_ctx *ctx)
{
	int ret;

	i_assert(!ctx->synced);

	if (!ctx->uidlist->initial_read) {
		/* first time reading the uidlist,
		   no locking yet */
		if (maildir_uidlist_update(ctx->uidlist) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 0;
	}

	/* lock and update uidlist to see if it's just been added */
	ret = maildir_uidlist_try_lock(ctx->uidlist);
	if (ret <= 0) {
		if (ret == 0) {
			ctx->locked = TRUE;
			return -1;
		}
		ctx->failed = TRUE;
		return -1;
	}
	if (maildir_uidlist_update(ctx->uidlist) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	ctx->synced = TRUE;
	return 1;
}

static int
maildir_uidlist_sync_next_partial(struct maildir_uidlist_sync_ctx *ctx,
				  const char *filename,
				  enum maildir_uidlist_rec_flag flags)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct maildir_uidlist_rec *rec;

	/* we'll update uidlist directly */
	rec = hash_lookup(uidlist->files, filename);
	i_assert(rec != NULL || ctx->synced);

	if (rec == NULL) {
		if (ctx->new_files_count == 0) {
			ctx->first_new_pos =
				buffer_get_used_size(uidlist->record_buf) /
				sizeof(rec);
		}
		ctx->new_files_count++;

		if (uidlist->record_pool == NULL) {
			uidlist->record_pool =
				pool_alloconly_create("uidlist record_pool",
						      1024);
		}

		rec = p_new(uidlist->record_pool,
			    struct maildir_uidlist_rec, 1);
		rec->uid = (uint32_t)-1;
		buffer_append(uidlist->record_buf, &rec, sizeof(rec));
	}

	if ((flags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0 &&
	    rec->uid != (uint32_t)-1)
		maildir_uidlist_mark_recent(uidlist, rec->uid);

	rec->flags = (rec->flags | flags) & ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	rec->filename = p_strdup(uidlist->record_pool, filename);
	hash_insert(uidlist->files, rec->filename, rec);
	return 1;
}

int maildir_uidlist_sync_next_pre(struct maildir_uidlist_sync_ctx *ctx,
				  const char *filename)
{
	int ret;

	if (!ctx->synced &&
	    hash_lookup(ctx->uidlist->files, filename) == NULL &&
	    (ctx->partial || hash_lookup(ctx->files, filename) == NULL)) {
		if (ctx->locked)
			return 0;

		ret = maildir_uidlist_sync_uidlist(ctx);
		if (ret < 0)
			return ctx->locked ? 0 : -1;
		if (ret == 0)
			return maildir_uidlist_sync_next_pre(ctx, filename);
	}

	return 1;
}

int maildir_uidlist_sync_next(struct maildir_uidlist_sync_ctx *ctx,
			      const char *filename,
			      enum maildir_uidlist_rec_flag flags)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct maildir_uidlist_rec *rec, *old_rec;

	if (ctx->failed)
		return -1;

	if (ctx->partial)
		return maildir_uidlist_sync_next_partial(ctx, filename, flags);

	rec = hash_lookup(ctx->files, filename);
	if (rec != NULL) {
		if ((rec->flags & (MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				   MAILDIR_UIDLIST_REC_FLAG_MOVED)) == 0) {
			/* possibly duplicate */
			return 0;
		}

		rec->flags &= ~(MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				MAILDIR_UIDLIST_REC_FLAG_MOVED);
	} else {
		old_rec = hash_lookup(uidlist->files, filename);
		i_assert(old_rec != NULL || ctx->synced);

		rec = p_new(ctx->record_pool, struct maildir_uidlist_rec, 1);

		if (old_rec != NULL)
			*rec = *old_rec;
		else {
			rec->uid = (uint32_t)-1;
			ctx->new_files_count++;
		}

		buffer_append(ctx->record_buf, &rec, sizeof(rec));
	}

	if ((flags & MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0 &&
	    rec->uid != (uint32_t)-1)
		maildir_uidlist_mark_recent(uidlist, rec->uid);

	rec->flags = (rec->flags | flags) & ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	rec->filename = p_strdup(ctx->record_pool, filename);
	hash_insert(ctx->files, rec->filename, rec);
	return 1;
}

static int maildir_time_cmp(const void *p1, const void *p2)
{
	const struct maildir_uidlist_rec *const *rec1 = p1, *const *rec2 = p2;
	const char *s1 = (*rec1)->filename, *s2 = (*rec2)->filename;
	time_t t1 = 0, t2 = 0;

	/* we have to do numeric comparision, strcmp() will break when
	   there's different amount of digits (mostly the 999999999 ->
	   1000000000 change in Sep 9 2001) */
	while (*s1 >= '0' && *s1 <= '9') {
		t1 = t1*10 + (*s1 - '0');
		s1++;
	}
	while (*s2 >= '0' && *s2 <= '9') {
		t2 = t2*10 + (*s2 - '0');
		s2++;
	}

	return t1 < t2 ? -1 : t1 > t2 ? 1 : 0;
}

static void maildir_uidlist_assign_uids(struct maildir_uidlist *uidlist,
					unsigned int first_new_pos)
{
	struct maildir_uidlist_rec **rec_p;
	unsigned int dest;
	size_t size;

	i_assert(UIDLIST_IS_LOCKED(uidlist));

	rec_p = buffer_get_modifyable_data(uidlist->record_buf, &size);
	size /= sizeof(*rec_p);

	/* sort new files and assign UIDs for them */
	qsort(rec_p + first_new_pos, size - first_new_pos,
	      sizeof(*rec_p), maildir_time_cmp);
	for (dest = first_new_pos; dest < size; dest++) {
		i_assert(rec_p[dest]->uid == (uint32_t)-1);
		rec_p[dest]->uid = uidlist->next_uid++;
		rec_p[dest]->flags &= ~MAILDIR_UIDLIST_REC_FLAG_MOVED;

		if ((rec_p[dest]->flags &
		     MAILDIR_UIDLIST_REC_FLAG_RECENT) != 0)
			maildir_uidlist_mark_recent(uidlist, rec_p[dest]->uid);
	}
}

static int maildir_uid_cmp(const void *p1, const void *p2)
{
	const struct maildir_uidlist_rec *const *rec1 = p1, *const *rec2 = p2;

	return (*rec1)->uid < (*rec2)->uid ? -1 :
		(*rec1)->uid > (*rec2)->uid ? 1 : 0;
}

static void maildir_uidlist_swap(struct maildir_uidlist_sync_ctx *ctx)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct maildir_uidlist_rec **rec_p;
	size_t size;

	/* buffer is unsorted, sort it by UID */
	rec_p = buffer_get_modifyable_data(ctx->record_buf, &size);
	size /= sizeof(*rec_p);
	qsort(rec_p, size, sizeof(*rec_p), maildir_uid_cmp);

	buffer_free(uidlist->record_buf);
	uidlist->record_buf = ctx->record_buf;
	ctx->record_buf = NULL;

	hash_destroy(uidlist->files);
	uidlist->files = ctx->files;
	ctx->files = NULL;

	if (uidlist->record_pool != NULL)
		pool_unref(uidlist->record_pool);
	uidlist->record_pool = ctx->record_pool;
	ctx->record_pool = NULL;

	if (ctx->new_files_count != 0) {
		maildir_uidlist_assign_uids(uidlist,
					    size - ctx->new_files_count);
	}
}

int maildir_uidlist_sync_finish(struct maildir_uidlist_sync_ctx *ctx)
{
	if (!ctx->partial) {
		if (!ctx->failed && !ctx->locked)
			maildir_uidlist_swap(ctx);
	} else {
		if (ctx->new_files_count != 0) {
			maildir_uidlist_assign_uids(ctx->uidlist,
						    ctx->first_new_pos);
		}
	}

	ctx->finished = TRUE;
	ctx->uidlist->initial_sync = TRUE;
	return !ctx->locked;
}

int maildir_uidlist_sync_deinit(struct maildir_uidlist_sync_ctx *ctx)
{
	int ret = ctx->failed ? -1 : 0;

	if (!ctx->finished)
		maildir_uidlist_sync_finish(ctx);

	if (ctx->new_files_count != 0 && !ctx->failed && !ctx->locked)
		ret = maildir_uidlist_rewrite(ctx->uidlist);

	if (ctx->partial)
		maildir_uidlist_mark_all(ctx->uidlist, FALSE);

	if (UIDLIST_IS_LOCKED(ctx->uidlist))
		maildir_uidlist_unlock(ctx->uidlist);

	if (ctx->files != NULL)
		hash_destroy(ctx->files);
	if (ctx->record_pool != NULL)
		pool_unref(ctx->record_pool);
	if (ctx->record_buf != NULL)
		buffer_free(ctx->record_buf);
	i_free(ctx);
	return ret;
}

void maildir_uidlist_add_flags(struct maildir_uidlist *uidlist,
			       const char *filename,
			       enum maildir_uidlist_rec_flag flags)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_lookup(uidlist->files, filename);
	i_assert(rec != NULL);

	rec->flags |= flags;
}

struct maildir_uidlist_iter_ctx *
maildir_uidlist_iter_init(struct maildir_uidlist *uidlist)
{
	struct maildir_uidlist_iter_ctx *ctx;
	size_t size;

	ctx = i_new(struct maildir_uidlist_iter_ctx, 1);
	ctx->next = buffer_get_data(uidlist->record_buf, &size);
	size /= sizeof(*ctx->next);
	ctx->end = ctx->next + size;
	return ctx;
}

int maildir_uidlist_iter_next(struct maildir_uidlist_iter_ctx *ctx,
			      uint32_t *uid_r,
			      enum maildir_uidlist_rec_flag *flags_r,
			      const char **filename_r)
{
	if (ctx->next == ctx->end)
		return 0;

	*uid_r = (*ctx->next)->uid;
	*flags_r = (*ctx->next)->flags;
	*filename_r = (*ctx->next)->filename;
	ctx->next++;
	return 1;
}

void maildir_uidlist_iter_deinit(struct maildir_uidlist_iter_ctx *ctx)
{
	i_free(ctx);
}
