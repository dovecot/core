/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

/*
   Version 1 format has been used for most versions of Dovecot up to v1.0.x.
   It's also compatible with Courier IMAP's courierimapuiddb file.
   The format is:

   header: 1 <uid validity> <next uid>
   entry: <uid> <filename>

   --

   Version 2 format was written by a few development Dovecot versions, but
   v1.0.x still parses the format. The format has <flags> field after <uid>.

   --

   Version 3 format is an extensible format used by Dovecot v1.1 and later.
   It's also parsed by v1.0.2 (and later). The format is:

   header: 3 [<key><value> ...]
   entry: <uid> [<key><value> ...] :<filename>

   See enum maildir_uidlist_*_ext_key for used keys.
*/

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "file-dotlock.h"
#include "nfs-workarounds.h"
#include "eacces-error.h"
#include "maildir-storage.h"
#include "maildir-filename.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <sys/stat.h>

/* NFS: How many times to retry reading dovecot-uidlist file if ESTALE
   error occurs in the middle of reading it */
#define UIDLIST_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT

#define UIDLIST_VERSION 3
#define UIDLIST_COMPRESS_PERCENTAGE 75

#define UIDLIST_IS_LOCKED(uidlist) \
	((uidlist)->lock_count > 0)

struct maildir_uidlist_rec {
	uint32_t uid;
	uint32_t flags;
	char *filename;
	unsigned char *extensions; /* <data>\0[<data>\0 ...]\0 */
};
ARRAY_DEFINE_TYPE(maildir_uidlist_rec_p, struct maildir_uidlist_rec *);

HASH_TABLE_DEFINE_TYPE(path_to_maildir_uidlist_rec,
		       char *, struct maildir_uidlist_rec *);

struct maildir_uidlist {
	struct mailbox *box;
	char *path;
	struct maildir_index_header *mhdr;

	int fd;
	dev_t fd_dev;
	ino_t fd_ino;
	off_t fd_size;

	unsigned int lock_count;

	struct dotlock_settings dotlock_settings;
	struct dotlock *dotlock;

	pool_t record_pool;
	ARRAY_TYPE(maildir_uidlist_rec_p) records;
	HASH_TABLE_TYPE(path_to_maildir_uidlist_rec) files;
	unsigned int change_counter;

	unsigned int version;
	unsigned int uid_validity, next_uid, prev_read_uid, last_seen_uid;
	unsigned int hdr_next_uid;
	unsigned int read_records_count, read_line_count;
	uoff_t last_read_offset;
	string_t *hdr_extensions;

	guid_128_t mailbox_guid;

	bool recreate:1;
	bool recreate_on_change:1;
	bool initial_read:1;
	bool initial_hdr_read:1;
	bool retry_rewind:1;
	bool locked_refresh:1;
	bool unsorted:1;
	bool have_mailbox_guid:1;
	bool opened_readonly:1;
};

struct maildir_uidlist_sync_ctx {
	struct maildir_uidlist *uidlist;
	enum maildir_uidlist_sync_flags sync_flags;

	pool_t record_pool;
	ARRAY_TYPE(maildir_uidlist_rec_p) records;
	HASH_TABLE_TYPE(path_to_maildir_uidlist_rec) files;

	unsigned int first_unwritten_pos, first_new_pos;
	unsigned int new_files_count;
	unsigned int finish_change_counter;

	bool partial:1;
	bool finished:1;
	bool changed:1;
	bool failed:1;
	bool locked:1;
};

struct maildir_uidlist_iter_ctx {
	struct maildir_uidlist *uidlist;
	struct maildir_uidlist_rec *const *next, *const *end;

	unsigned int change_counter;
	uint32_t prev_uid;
};

static int maildir_uidlist_open_latest(struct maildir_uidlist *uidlist);
static bool maildir_uidlist_iter_next_rec(struct maildir_uidlist_iter_ctx *ctx,
					  struct maildir_uidlist_rec **rec_r);

static int maildir_uidlist_lock_timeout(struct maildir_uidlist *uidlist,
					bool nonblock, bool refresh,
					bool refresh_when_locked)
{
	struct mailbox *box = uidlist->box;
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	const char *path = uidlist->path;
	mode_t old_mask;
	const enum dotlock_create_flags dotlock_flags =
		nonblock ? DOTLOCK_CREATE_FLAG_NONBLOCK : 0;
	int i, ret;

	if (uidlist->lock_count > 0) {
		if (!uidlist->locked_refresh && refresh_when_locked) {
			if (maildir_uidlist_refresh(uidlist) < 0)
				return -1;
		}
		uidlist->lock_count++;
		return 1;
	}

        index_storage_lock_notify_reset(box);

	for (i = 0;; i++) {
		old_mask = umask(0777 & ~perm->file_create_mode);
		ret = file_dotlock_create(&uidlist->dotlock_settings, path,
					  dotlock_flags, &uidlist->dotlock);
		umask(old_mask);
		if (ret > 0)
			break;

		/* failure */
		if (ret == 0) {
			mail_storage_set_error(box->storage,
				MAIL_ERROR_TEMP, MAIL_ERRSTR_LOCK_TIMEOUT);
			return 0;
		}
		if (errno != ENOENT || i == MAILDIR_DELETE_RETRY_COUNT) {
			if (errno == EACCES) {
				mailbox_set_critical(box, "%s",
					eacces_error_get_creating("file_dotlock_create", path));
			} else {
				mailbox_set_critical(box,
					"file_dotlock_create(%s) failed: %m",
					path);
			}
			return -1;
		}
		/* the control dir doesn't exist. create it unless the whole
		   mailbox was just deleted. */
		if (!maildir_set_deleted(uidlist->box))
			return -1;
	}

	uidlist->lock_count++;
	uidlist->locked_refresh = FALSE;

	if (refresh) {
		/* make sure we have the latest changes before
		   changing anything */
		if (maildir_uidlist_refresh(uidlist) < 0) {
			maildir_uidlist_unlock(uidlist);
			return -1;
		}
	}
	return 1;
}

int maildir_uidlist_lock(struct maildir_uidlist *uidlist)
{
	return maildir_uidlist_lock_timeout(uidlist, FALSE, TRUE, FALSE);
}

int maildir_uidlist_try_lock(struct maildir_uidlist *uidlist)
{
	return maildir_uidlist_lock_timeout(uidlist, TRUE, TRUE, FALSE);
}

int maildir_uidlist_lock_touch(struct maildir_uidlist *uidlist)
{
	i_assert(UIDLIST_IS_LOCKED(uidlist));

	return file_dotlock_touch(uidlist->dotlock);
}

bool maildir_uidlist_is_locked(struct maildir_uidlist *uidlist)
{
	return UIDLIST_IS_LOCKED(uidlist);
}

bool maildir_uidlist_is_read(struct maildir_uidlist *uidlist)
{
	return uidlist->initial_read;
}

bool maildir_uidlist_is_open(struct maildir_uidlist *uidlist)
{
	return uidlist->fd != -1;
}

void maildir_uidlist_unlock(struct maildir_uidlist *uidlist)
{
	i_assert(uidlist->lock_count > 0);

	if (--uidlist->lock_count > 0)
		return;

	uidlist->locked_refresh = FALSE;
	file_dotlock_delete(&uidlist->dotlock);
}

static bool dotlock_callback(unsigned int secs_left, bool stale, void *context)
{
	struct mailbox *box = context;

	index_storage_lock_notify(box, stale ?
				  MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE :
				  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
				  secs_left);
	return TRUE;
}

struct maildir_uidlist *maildir_uidlist_init(struct maildir_mailbox *mbox)
{
	struct mailbox *box = &mbox->box;
	struct maildir_uidlist *uidlist;
	const char *control_dir;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_CONTROL,
				&control_dir) <= 0)
		i_unreached();

	uidlist = i_new(struct maildir_uidlist, 1);
	uidlist->box = box;
	uidlist->mhdr = &mbox->maildir_hdr;
	uidlist->fd = -1;
	uidlist->path = i_strconcat(control_dir, "/"MAILDIR_UIDLIST_NAME, NULL);
	i_array_init(&uidlist->records, 128);
	hash_table_create(&uidlist->files, default_pool, 4096,
			  maildir_filename_base_hash,
			  maildir_filename_base_cmp);
	uidlist->next_uid = 1;
	uidlist->hdr_extensions = str_new(default_pool, 128);

	uidlist->dotlock_settings.use_io_notify = TRUE;
	uidlist->dotlock_settings.use_excl_lock =
		box->storage->set->dotlock_use_excl;
	uidlist->dotlock_settings.nfs_flush =
		box->storage->set->mail_nfs_storage;
	uidlist->dotlock_settings.timeout =
		mail_storage_get_lock_timeout(box->storage,
			MAILDIR_UIDLIST_LOCK_STALE_TIMEOUT + 2);
	uidlist->dotlock_settings.stale_timeout =
		MAILDIR_UIDLIST_LOCK_STALE_TIMEOUT;
	uidlist->dotlock_settings.callback = dotlock_callback;
	uidlist->dotlock_settings.context = box;
	uidlist->dotlock_settings.temp_prefix = mbox->storage->temp_prefix;
	return uidlist;
}

static void maildir_uidlist_close(struct maildir_uidlist *uidlist)
{
	if (uidlist->fd != -1) {
		if (close(uidlist->fd) < 0) {
			mailbox_set_critical(uidlist->box,
				"close(%s) failed: %m", uidlist->path);
		}
		uidlist->fd = -1;
		uidlist->fd_ino = 0;
	}
	uidlist->last_read_offset = 0;
	uidlist->read_line_count = 0;
}

static void maildir_uidlist_reset(struct maildir_uidlist *uidlist)
{
	maildir_uidlist_close(uidlist);
	uidlist->last_seen_uid = 0;
	uidlist->initial_hdr_read = FALSE;
	uidlist->read_records_count = 0;

	hash_table_clear(uidlist->files, FALSE);
	array_clear(&uidlist->records);
}

void maildir_uidlist_deinit(struct maildir_uidlist **_uidlist)
{
	struct maildir_uidlist *uidlist = *_uidlist;

	i_assert(!UIDLIST_IS_LOCKED(uidlist));

	*_uidlist = NULL;
	(void)maildir_uidlist_update(uidlist);
	maildir_uidlist_close(uidlist);

	hash_table_destroy(&uidlist->files);
	pool_unref(&uidlist->record_pool);

	array_free(&uidlist->records);
	str_free(&uidlist->hdr_extensions);
	i_free(uidlist->path);
	i_free(uidlist);
}

static int maildir_uid_cmp(struct maildir_uidlist_rec *const *rec1,
			   struct maildir_uidlist_rec *const *rec2)
{
	return (*rec1)->uid < (*rec2)->uid ? -1 :
		(*rec1)->uid > (*rec2)->uid ? 1 : 0;
}

static void ATTR_FORMAT(2, 3)
maildir_uidlist_set_corrupted(struct maildir_uidlist *uidlist,
			      const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (uidlist->retry_rewind) {
		mailbox_set_critical(uidlist->box,
			"Broken or unexpectedly changed file %s "
			"line %u: %s - re-reading from beginning",
			uidlist->path, uidlist->read_line_count,
			t_strdup_vprintf(fmt, args));
	} else {
		mailbox_set_critical(uidlist->box, "Broken file %s line %u: %s",
			uidlist->path, uidlist->read_line_count,
			t_strdup_vprintf(fmt, args));
	}
	va_end(args);
}

static void maildir_uidlist_update_hdr(struct maildir_uidlist *uidlist,
				       const struct stat *st)
{
	struct maildir_index_header *mhdr = uidlist->mhdr;

	if (mhdr->uidlist_mtime == 0 && uidlist->version != UIDLIST_VERSION) {
		/* upgrading from older version. don't update the
		   uidlist times until it uses the new format */
		uidlist->recreate = TRUE;
		return;
	}
	mhdr->uidlist_mtime = st->st_mtime;
	mhdr->uidlist_mtime_nsecs = ST_MTIME_NSEC(*st);
	mhdr->uidlist_size = st->st_size;
}

static unsigned int
maildir_uidlist_records_array_delete(struct maildir_uidlist *uidlist,
				     struct maildir_uidlist_rec *rec)
{
	struct maildir_uidlist_rec *const *recs, *const *pos;
	unsigned int idx, count;

	recs = array_get(&uidlist->records, &count);
	if (!uidlist->unsorted) {
		pos = array_bsearch(&uidlist->records, &rec, maildir_uid_cmp);
		i_assert(pos != NULL);
		idx = pos - recs;
	} else {
		for (idx = 0; idx < count; idx++) {
			if (recs[idx]->uid == rec->uid)
				break;
		}
		i_assert(idx != count);
	}
	array_delete(&uidlist->records, idx, 1);
	return idx;
}

static bool
maildir_uidlist_read_extended(struct maildir_uidlist *uidlist,
			      const char **line_p,
			      struct maildir_uidlist_rec *rec)
{
	const char *start, *line = *line_p;
	buffer_t *buf;

	buf = t_buffer_create(128);
	while (*line != '\0' && *line != ':') {
		/* skip over an extension field */
		start = line;
		while (*line != ' ' && *line != '\0') line++;
		if (MAILDIR_UIDLIST_REC_EXT_KEY_IS_VALID(*start)) {
			buffer_append(buf, start, line - start);
			buffer_append_c(buf, '\0');
		} else {
			maildir_uidlist_set_corrupted(uidlist,
				"Invalid extension record, removing: %s",
				t_strdup_until(start, line));
			uidlist->recreate = TRUE;
		}
		while (*line == ' ') line++;
	}

	if (buf->used > 0) {
		/* save the extensions */
		buffer_append_c(buf, '\0');
		rec->extensions = p_malloc(uidlist->record_pool, buf->used);
		memcpy(rec->extensions, buf->data, buf->used);
	}

	if (*line == ':')
		line++;
	if (*line == '\0')
		return FALSE;

	*line_p = line;
	return TRUE;
}

static bool maildir_uidlist_next(struct maildir_uidlist *uidlist,
				 const char *line)
{
	struct maildir_uidlist_rec *rec, *old_rec, *const *recs;
	unsigned int count;
	uint32_t uid;

	uid = 0;
	while (*line >= '0' && *line <= '9') {
		uid = uid*10 + (*line - '0');
		line++;
	}

	if (uid == 0 || *line != ' ') {
		/* invalid file */
		maildir_uidlist_set_corrupted(uidlist, "Invalid data: %s",
					      line);
		return FALSE;
	}
	if (uid <= uidlist->prev_read_uid) {
		maildir_uidlist_set_corrupted(uidlist, 
					      "UIDs not ordered (%u >= %u)",
					      uid, uidlist->prev_read_uid);
		return FALSE;
	}
	if (uid >= (uint32_t)-1) {
		maildir_uidlist_set_corrupted(uidlist,
					      "UID too high (%u)", uid);
		return FALSE;
	}
	uidlist->prev_read_uid = uid;

	if (uid <= uidlist->last_seen_uid) {
		/* we already have this */
		return TRUE;
	}
        uidlist->last_seen_uid = uid;

	if (uid >= uidlist->next_uid && uidlist->version == 1) {
		maildir_uidlist_set_corrupted(uidlist, 
			"UID larger than next_uid (%u >= %u)",
			uid, uidlist->next_uid);
		return FALSE;
	}

	rec = p_new(uidlist->record_pool, struct maildir_uidlist_rec, 1);
	rec->uid = uid;
	rec->flags = MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;

	while (*line == ' ') line++;

	if (uidlist->version == UIDLIST_VERSION) {
		/* read extended fields */
		bool ret;

		T_BEGIN {
			ret = maildir_uidlist_read_extended(uidlist, &line,
							    rec);
		} T_END;
		if (!ret) {
			maildir_uidlist_set_corrupted(uidlist, 
				"Invalid extended fields: %s", line);
			return FALSE;
		}
	}

	if (strchr(line, '/') != NULL) {
		maildir_uidlist_set_corrupted(uidlist, 
			"%s: Broken filename at line %u: %s",
			uidlist->path, uidlist->read_line_count, line);
		return FALSE;
	}

	old_rec = hash_table_lookup(uidlist->files, line);
	if (old_rec == NULL) {
		/* no conflicts */
	} else if (old_rec->uid == uid) {
		/* most likely this is a record we saved ourself, but couldn't
		   update last_seen_uid because uidlist wasn't refreshed while
		   it was locked.

		   another possibility is a duplicate file record. currently
		   it would be a bug, but not that big of a deal. also perhaps
		   in future such duplicate lines could be used to update
		   extended fields. so just let it through anyway.

		   we'll waste a bit of memory here by allocating the record
		   twice, but that's not really a problem.  */
		rec->filename = old_rec->filename;
		hash_table_update(uidlist->files, rec->filename, rec);
		uidlist->unsorted = TRUE;
		return TRUE;
	} else {
		/* This can happen if expunged file is moved back and the file
		   was appended to uidlist. */
		i_warning("%s: Duplicate file entry at line %u: "
			  "%s (uid %u -> %u)%s",
			  uidlist->path, uidlist->read_line_count, line,
			  old_rec->uid, uid, uidlist->retry_rewind ?
			  " - retrying by re-reading from beginning" : "");
		if (uidlist->retry_rewind)
			return FALSE;
		/* Delete the old UID */
		(void)maildir_uidlist_records_array_delete(uidlist, old_rec);
		/* Replace the old record with this new one */
		*old_rec = *rec;
		rec = old_rec;
		uidlist->recreate = TRUE;
	}

	recs = array_get(&uidlist->records, &count);
	if (count > 0 && recs[count-1]->uid > uid) {
		/* we most likely have some records in the array that we saved
		   ourself without refreshing uidlist */
		uidlist->unsorted = TRUE;
	}

	rec->filename = p_strdup(uidlist->record_pool, line);
	hash_table_update(uidlist->files, rec->filename, rec);
	array_push_back(&uidlist->records, &rec);
	return TRUE;
}

static int
maildir_uidlist_read_v3_header(struct maildir_uidlist *uidlist,
			       const char *line,
			       unsigned int *uid_validity_r,
			       unsigned int *next_uid_r)
{
	char key;

	str_truncate(uidlist->hdr_extensions, 0);
	while (*line != '\0') {
		const char *value;

		key = *line;
		value = ++line;
		while (*line != '\0' && *line != ' ') line++;
		value = t_strdup_until(value, line);

		switch (key) {
		case MAILDIR_UIDLIST_HDR_EXT_UID_VALIDITY:
			if (str_to_uint(value, uid_validity_r) < 0) {
				maildir_uidlist_set_corrupted(uidlist,
					"Invalid mailbox UID_VALIDITY: %s", value);
				return -1;
			}
			break;
		case MAILDIR_UIDLIST_HDR_EXT_NEXT_UID:
			if (str_to_uint(value, next_uid_r) < 0) {
				maildir_uidlist_set_corrupted(uidlist,
					"Invalid mailbox NEXT_UID: %s", value);
				return -1;
			}
			break;
		case MAILDIR_UIDLIST_HDR_EXT_GUID:
			if (guid_128_from_string(value,
						 uidlist->mailbox_guid) < 0) {
				maildir_uidlist_set_corrupted(uidlist,
					"Invalid mailbox GUID: %s", value);
				return -1;
			}
			uidlist->have_mailbox_guid = TRUE;
			break;
		default:
			if (str_len(uidlist->hdr_extensions) > 0)
				str_append_c(uidlist->hdr_extensions, ' ');
			str_printfa(uidlist->hdr_extensions,
				    "%c%s", key, value);
			break;
		}

		while (*line == ' ') line++;
	}
	return 0;
}

static int maildir_uidlist_read_header(struct maildir_uidlist *uidlist,
				       struct istream *input)
{
	unsigned int uid_validity = 0, next_uid = 0;
	const char *line;
	int ret;

	line = i_stream_read_next_line(input);
        if (line == NULL) {
                /* I/O error / empty file */
                return input->stream_errno == 0 ? 0 : -1;
	}
	uidlist->read_line_count = 1;

	if (*line < '0' || *line > '9' || line[1] != ' ') {
		maildir_uidlist_set_corrupted(uidlist,
			"Corrupted header (invalid version number)");
		return 0;
	}

	uidlist->version = *line - '0';
	line += 2;

	switch (uidlist->version) {
	case 1:
		if (sscanf(line, "%u %u", &uid_validity, &next_uid) != 2) {
			maildir_uidlist_set_corrupted(uidlist,
				"Corrupted header (version 1)");
			return 0;
		}
		break;
	case UIDLIST_VERSION:
		T_BEGIN {
			ret = maildir_uidlist_read_v3_header(uidlist, line,
							     &uid_validity,
							     &next_uid);
		} T_END;
		if (ret < 0)
			return 0;
		break;
	default:
		maildir_uidlist_set_corrupted(uidlist, "Unsupported version %u",
					      uidlist->version);
		return 0;
	}

	if (uid_validity == 0 || next_uid == 0) {
		maildir_uidlist_set_corrupted(uidlist,
			"Broken header (uidvalidity = %u, next_uid=%u)",
			uid_validity, next_uid);
		return 0;
	}

	if (uid_validity == uidlist->uid_validity &&
	    next_uid < uidlist->hdr_next_uid) {
		maildir_uidlist_set_corrupted(uidlist,
			"next_uid header was lowered (%u -> %u)",
			uidlist->hdr_next_uid, next_uid);
		return 0;
	}

	uidlist->uid_validity = uid_validity;
	uidlist->next_uid = next_uid;
	uidlist->hdr_next_uid = next_uid;
	return 1;
}

static void maildir_uidlist_records_sort_by_uid(struct maildir_uidlist *uidlist)
{
	array_sort(&uidlist->records, maildir_uid_cmp);
	uidlist->unsorted = FALSE;
}

static int
maildir_uidlist_update_read(struct maildir_uidlist *uidlist,
			    bool *retry_r, bool try_retry)
{
	const char *line;
	uint32_t orig_next_uid, orig_uid_validity;
	struct istream *input;
	struct stat st;
	uoff_t last_read_offset;
	int fd, ret;
	bool readonly = FALSE;

	*retry_r = FALSE;

	if (uidlist->fd == -1) {
		fd = nfs_safe_open(uidlist->path, O_RDWR);
		if (fd == -1 && errno == EACCES) {
			fd = nfs_safe_open(uidlist->path, O_RDONLY);
			readonly = TRUE;
		}
		if (fd == -1) {
			if (errno != ENOENT) {
				mailbox_set_critical(uidlist->box,
					"open(%s) failed: %m", uidlist->path);
				return -1;
			}
			return 0;
		}
		last_read_offset = 0;
	} else {
		/* the file was updated */
		fd = uidlist->fd;
		if (lseek(fd, 0, SEEK_SET) < 0) {
			if (errno == ESTALE && try_retry) {
				*retry_r = TRUE;
				return -1;
			}
			mailbox_set_critical(uidlist->box,
				"lseek(%s) failed: %m", uidlist->path);
			return -1;
		}
		uidlist->fd = -1;
		uidlist->fd_ino = 0;
		last_read_offset = uidlist->last_read_offset;
		uidlist->last_read_offset = 0;
	}

	if (fstat(fd, &st) < 0) {
                i_close_fd(&fd);
                if (errno == ESTALE && try_retry) {
                        *retry_r = TRUE;
                        return -1;
                }
                mailbox_set_critical(uidlist->box,
			"fstat(%s) failed: %m", uidlist->path);
		return -1;
	}

	if (uidlist->record_pool == NULL) {
		uidlist->record_pool =
			pool_alloconly_create(MEMPOOL_GROWING
					      "uidlist record_pool",
					      nearest_power(st.st_size -
							    st.st_size/8));
	}

	input = i_stream_create_fd(fd, (size_t)-1);
	i_stream_seek(input, last_read_offset);

	orig_uid_validity = uidlist->uid_validity;
	orig_next_uid = uidlist->next_uid;
	ret = input->v_offset != 0 ? 1 :
		maildir_uidlist_read_header(uidlist, input);
	if (ret > 0) {
		uidlist->prev_read_uid = 0;
		uidlist->change_counter++;
		uidlist->retry_rewind = last_read_offset != 0 && try_retry;

		ret = 1;
		while ((line = i_stream_read_next_line(input)) != NULL) {
			uidlist->read_records_count++;
			uidlist->read_line_count++;
			if (!maildir_uidlist_next(uidlist, line)) {
				if (!uidlist->retry_rewind)
					ret = 0;
				else {
					ret = -1;
					*retry_r = TRUE;
				}
				break;
			}
                }
		uidlist->retry_rewind = FALSE;
		if (input->stream_errno != 0)
                        ret = -1;

		if (uidlist->unsorted) {
			uidlist->recreate_on_change = TRUE;
			maildir_uidlist_records_sort_by_uid(uidlist);
		}
		if (uidlist->next_uid <= uidlist->prev_read_uid)
			uidlist->next_uid = uidlist->prev_read_uid + 1;
		if (ret > 0 && uidlist->uid_validity != orig_uid_validity &&
		    orig_uid_validity != 0) {
			uidlist->recreate = TRUE;
		} else if (ret > 0 && uidlist->next_uid < orig_next_uid) {
			mailbox_set_critical(uidlist->box,
				"%s: next_uid was lowered (%u -> %u, hdr=%u)",
				uidlist->path, orig_next_uid,
				uidlist->next_uid, uidlist->hdr_next_uid);
			uidlist->recreate = TRUE;
			uidlist->next_uid = orig_next_uid;
		}
	}

        if (ret == 0) {
                /* file is broken */
                i_unlink(uidlist->path);
        } else if (ret > 0) {
                /* success */
		if (readonly)
			uidlist->recreate_on_change = TRUE;
		uidlist->fd = fd;
		uidlist->fd_dev = st.st_dev;
		uidlist->fd_ino = st.st_ino;
		uidlist->fd_size = st.st_size;
		uidlist->last_read_offset = input->v_offset;
		maildir_uidlist_update_hdr(uidlist, &st);
        } else if (!*retry_r) {
                /* I/O error */
                if (input->stream_errno == ESTALE && try_retry)
			*retry_r = TRUE;
		else {
			mailbox_set_critical(uidlist->box,
				"read(%s) failed: %s", uidlist->path,
				i_stream_get_error(input));
		}
		uidlist->last_read_offset = 0;
	}

	i_stream_destroy(&input);
	if (ret <= 0) {
		if (close(fd) < 0) {
			mailbox_set_critical(uidlist->box,
				"close(%s) failed: %m", uidlist->path);
		}
	}
	return ret;
}

static int
maildir_uidlist_stat(struct maildir_uidlist *uidlist, struct stat *st_r)
{
	struct mail_storage *storage = uidlist->box->storage;

	if (storage->set->mail_nfs_storage) {
		nfs_flush_file_handle_cache(uidlist->path);
		nfs_flush_attr_cache_unlocked(uidlist->path);
	}
	if (nfs_safe_stat(uidlist->path, st_r) < 0) {
		if (errno != ENOENT) {
			mailbox_set_critical(uidlist->box,
				"stat(%s) failed: %m", uidlist->path);
			return -1;
		}
		return 0;
	}
	return 1;
}

static int
maildir_uidlist_has_changed(struct maildir_uidlist *uidlist, bool *recreated_r)
{
	struct mail_storage *storage = uidlist->box->storage;
        struct stat st;
	int ret;

	*recreated_r = FALSE;

	if ((ret = maildir_uidlist_stat(uidlist, &st)) < 0)
		return -1;
	if (ret == 0) {
		*recreated_r = TRUE;
		return 1;
	}

	if (st.st_ino != uidlist->fd_ino ||
	    !CMP_DEV_T(st.st_dev, uidlist->fd_dev)) {
		/* file recreated */
		*recreated_r = TRUE;
		return 1;
	}

	if (storage->set->mail_nfs_storage) {
		/* NFS: either the file hasn't been changed, or it has already
		   been deleted and the inodes just happen to be the same.
		   check if the fd is still valid. */
		if (fstat(uidlist->fd, &st) < 0) {
			if (errno == ESTALE) {
				*recreated_r = TRUE;
				return 1;
			}
			mailbox_set_critical(uidlist->box,
				"fstat(%s) failed: %m", uidlist->path);
			return -1;
		}
	}

	if (st.st_size != uidlist->fd_size) {
		/* file modified but not recreated */
		return 1;
	} else {
		/* unchanged */
		return 0;
	}
}

static int maildir_uidlist_open_latest(struct maildir_uidlist *uidlist)
{
	bool recreated;
	int ret;

	if (uidlist->fd != -1) {
		ret = maildir_uidlist_has_changed(uidlist, &recreated);
		if (ret <= 0) {
			if (UIDLIST_IS_LOCKED(uidlist))
				uidlist->locked_refresh = TRUE;
			return ret < 0 ? -1 : 1;
		}

		if (!recreated)
			return 0;
		maildir_uidlist_reset(uidlist);
	}

	uidlist->fd = nfs_safe_open(uidlist->path, O_RDWR);
	if (uidlist->fd == -1 && errno == EACCES) {
		uidlist->fd = nfs_safe_open(uidlist->path, O_RDONLY);
		uidlist->recreate_on_change = TRUE;
	}
	if (uidlist->fd == -1 && errno != ENOENT) {
		mailbox_set_critical(uidlist->box,
			"open(%s) failed: %m", uidlist->path);
		return -1;
	}
	return 0;
}

int maildir_uidlist_refresh(struct maildir_uidlist *uidlist)
{
        unsigned int i;
        bool retry;
        int ret;

	if (maildir_uidlist_open_latest(uidlist) < 0)
		return -1;

        for (i = 0; ; i++) {
		ret = maildir_uidlist_update_read(uidlist, &retry,
						i < UIDLIST_ESTALE_RETRY_COUNT);
		if (!retry)
			break;
		/* ESTALE - try reopening and rereading */
		maildir_uidlist_close(uidlist);
        }
	if (ret >= 0) {
		uidlist->initial_read = TRUE;
		uidlist->initial_hdr_read = TRUE;
		if (UIDLIST_IS_LOCKED(uidlist))
			uidlist->locked_refresh = TRUE;
		if (!uidlist->have_mailbox_guid) {
			uidlist->recreate = TRUE;
			(void)maildir_uidlist_update(uidlist);
		}
	}
        return ret;
}

int maildir_uidlist_refresh_fast_init(struct maildir_uidlist *uidlist)
{
	const struct maildir_index_header *mhdr = uidlist->mhdr;
	struct mail_index *index = uidlist->box->index;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	struct stat st;
	int ret;

	i_assert(UIDLIST_IS_LOCKED(uidlist));

	if (uidlist->fd != -1)
		return maildir_uidlist_refresh(uidlist);

	if ((ret = maildir_uidlist_stat(uidlist, &st)) < 0)
		return ret;

	if (ret > 0 && st.st_size == mhdr->uidlist_size &&
	    st.st_mtime == (time_t)mhdr->uidlist_mtime &&
	    ST_NTIMES_EQUAL(ST_MTIME_NSEC(st), mhdr->uidlist_mtime_nsecs) &&
	    (!mail_index_is_in_memory(index) || st.st_mtime < ioloop_time-1)) {
		/* index is up-to-date. look up the uidvalidity and next-uid
		   from it. we'll need to create a new view temporarily to
		   make sure we get the latest values. */
		view = mail_index_view_open(index);
		hdr = mail_index_get_header(view);
		uidlist->uid_validity = hdr->uid_validity;
		uidlist->next_uid = hdr->next_uid;
		uidlist->initial_hdr_read = TRUE;
		mail_index_view_close(&view);

		if (UIDLIST_IS_LOCKED(uidlist))
			uidlist->locked_refresh = TRUE;
		return 1;
	} else {
		return maildir_uidlist_refresh(uidlist);
	}
}

static int
maildir_uid_bsearch_cmp(const uint32_t *uidp,
			struct maildir_uidlist_rec *const *recp)
{
	return *uidp < (*recp)->uid ? -1 :
		*uidp > (*recp)->uid ? 1 : 0;
}

static int
maildir_uidlist_lookup_rec(struct maildir_uidlist *uidlist, uint32_t uid,
			   struct maildir_uidlist_rec **rec_r)
{
	struct maildir_uidlist_rec *const *pos;

	if (!uidlist->initial_read) {
		/* first time we need to read uidlist */
		if (maildir_uidlist_refresh(uidlist) < 0)
			return -1;
	}

	pos = array_bsearch(&uidlist->records, &uid,
			    maildir_uid_bsearch_cmp);
	if (pos == NULL) {
		*rec_r = NULL;
		return 0;
	}
	*rec_r = *pos;
	return 1;
}

int maildir_uidlist_lookup(struct maildir_uidlist *uidlist, uint32_t uid,
			   enum maildir_uidlist_rec_flag *flags_r,
			   const char **fname_r)
{
	struct maildir_uidlist_rec *rec;
	int ret;

	if ((ret = maildir_uidlist_lookup_rec(uidlist, uid, &rec)) <= 0)
		return ret;

	*flags_r = rec->flags;
	*fname_r = rec->filename;
	return 1;
}

const char *
maildir_uidlist_lookup_ext(struct maildir_uidlist *uidlist, uint32_t uid,
			   enum maildir_uidlist_rec_ext_key key)
{
	struct maildir_uidlist_rec *rec;
	const unsigned char *p;
	int ret;

	ret = maildir_uidlist_lookup_rec(uidlist, uid, &rec);
	if (ret <= 0 || rec->extensions == NULL)
		return NULL;

	p = rec->extensions;
	while (*p != '\0') {
		/* <key><value>\0 */
		if (*p == (unsigned char)key)
			return (const char *)p + 1;

		p += strlen((const char *)p) + 1;
	}
	return NULL;
}

uint32_t maildir_uidlist_get_uid_validity(struct maildir_uidlist *uidlist)
{
	return uidlist->uid_validity;
}

uint32_t maildir_uidlist_get_next_uid(struct maildir_uidlist *uidlist)
{
	return !uidlist->initial_hdr_read ? 0 : uidlist->next_uid;
}

int maildir_uidlist_get_mailbox_guid(struct maildir_uidlist *uidlist,
				     guid_128_t mailbox_guid)
{
	if (!uidlist->initial_hdr_read) {
		if (maildir_uidlist_refresh(uidlist) < 0)
			return -1;
	}
	if (!uidlist->have_mailbox_guid) {
		uidlist->recreate = TRUE;
		if (maildir_uidlist_update(uidlist) < 0)
			return -1;
	}
	memcpy(mailbox_guid, uidlist->mailbox_guid, GUID_128_SIZE);
	return 0;
}

void maildir_uidlist_set_mailbox_guid(struct maildir_uidlist *uidlist,
				      const guid_128_t mailbox_guid)
{
	if (memcmp(uidlist->mailbox_guid, mailbox_guid,
		   sizeof(uidlist->mailbox_guid)) != 0) {
		memcpy(uidlist->mailbox_guid, mailbox_guid,
		       sizeof(uidlist->mailbox_guid));
		uidlist->recreate = TRUE;
	}
}

void maildir_uidlist_set_uid_validity(struct maildir_uidlist *uidlist,
				      uint32_t uid_validity)
{
	i_assert(uid_validity != 0);

	if (uid_validity != uidlist->uid_validity) {
		uidlist->uid_validity = uid_validity;
		uidlist->recreate = TRUE;
	}
}

void maildir_uidlist_set_next_uid(struct maildir_uidlist *uidlist,
				  uint32_t next_uid, bool force)
{
	if (uidlist->next_uid < next_uid || force) {
		i_assert(next_uid != 0);
		uidlist->next_uid = next_uid;
		uidlist->recreate = TRUE;
	}
}

static void
maildir_uidlist_rec_set_ext(struct maildir_uidlist_rec *rec, pool_t pool,
			    enum maildir_uidlist_rec_ext_key key,
			    const char *value)
{
	const unsigned char *p;
	buffer_t *buf;
	size_t len;

	/* copy existing extensions, except for the one we're updating */
	buf = t_buffer_create(128);
	if (rec->extensions != NULL) {
		p = rec->extensions;
		while (*p != '\0') {
			/* <key><value>\0 */
			i_assert(MAILDIR_UIDLIST_REC_EXT_KEY_IS_VALID(*p));

			len = strlen((const char *)p) + 1;
			if (*p != (unsigned char)key)
				buffer_append(buf, p, len);
			p += len;
		}
	}
	if (value != NULL) {
		buffer_append_c(buf, key);
		buffer_append(buf, value, strlen(value) + 1);
	}
	buffer_append_c(buf, '\0');

	rec->extensions = p_malloc(pool, buf->used);
	memcpy(rec->extensions, buf->data, buf->used);
}

static void ATTR_NULL(4)
maildir_uidlist_set_ext_internal(struct maildir_uidlist *uidlist, uint32_t uid,
				 enum maildir_uidlist_rec_ext_key key,
				 const char *value)
{
	struct maildir_uidlist_rec *rec;
	int ret;

	i_assert(MAILDIR_UIDLIST_REC_EXT_KEY_IS_VALID(key));

	ret = maildir_uidlist_lookup_rec(uidlist, uid, &rec);
	if (ret <= 0) {
		if (ret < 0)
			return;

		/* maybe it's a new message */
		if (maildir_uidlist_refresh(uidlist) < 0)
			return;
		if (maildir_uidlist_lookup_rec(uidlist, uid, &rec) <= 0) {
			/* message is already expunged, ignore */
			return;
		}
	}

	T_BEGIN {
		maildir_uidlist_rec_set_ext(rec, uidlist->record_pool,
					    key, value);
	} T_END;

	if (rec->uid != (uint32_t)-1) {
		/* message already exists in uidlist, need to recreate it */
		uidlist->recreate = TRUE;
	}
}

void maildir_uidlist_set_ext(struct maildir_uidlist *uidlist, uint32_t uid,
			     enum maildir_uidlist_rec_ext_key key,
			     const char *value)
{
	maildir_uidlist_set_ext_internal(uidlist, uid, key, value);
}

void maildir_uidlist_unset_ext(struct maildir_uidlist *uidlist, uint32_t uid,
			       enum maildir_uidlist_rec_ext_key key)
{
	maildir_uidlist_set_ext_internal(uidlist, uid, key, NULL);
}

static void
maildir_uidlist_generate_uid_validity(struct maildir_uidlist *uidlist)
{
	const struct mail_index_header *hdr;

	if (uidlist->box->opened) {
		hdr = mail_index_get_header(uidlist->box->view);
		if (hdr->uid_validity != 0) {
			uidlist->uid_validity = hdr->uid_validity;
			return;
		}
	}
	uidlist->uid_validity =
		maildir_get_uidvalidity_next(uidlist->box->list);
}

static int maildir_uidlist_write_fd(struct maildir_uidlist *uidlist, int fd,
				    const char *path, unsigned int first_idx,
				    uoff_t *file_size_r)
{
	struct mail_storage *storage = uidlist->box->storage;
	struct maildir_uidlist_iter_ctx *iter;
	struct ostream *output;
	struct maildir_uidlist_rec *rec;
	string_t *str;
	const unsigned char *p;
	const char *strp;
	size_t len;

	i_assert(fd != -1);

	output = o_stream_create_fd_file(fd, (uoff_t)-1, FALSE);
	o_stream_cork(output);
	str = t_str_new(512);

	if (output->offset == 0) {
		i_assert(first_idx == 0);
		uidlist->version = UIDLIST_VERSION;

		if (uidlist->uid_validity == 0)
			maildir_uidlist_generate_uid_validity(uidlist);
		if (!uidlist->have_mailbox_guid)
			guid_128_generate(uidlist->mailbox_guid);

		i_assert(uidlist->next_uid > 0);
		str_printfa(str, "%u %c%u %c%u %c%s", uidlist->version,
			    MAILDIR_UIDLIST_HDR_EXT_UID_VALIDITY,
			    uidlist->uid_validity,
			    MAILDIR_UIDLIST_HDR_EXT_NEXT_UID,
			    uidlist->next_uid,
			    MAILDIR_UIDLIST_HDR_EXT_GUID,
			    guid_128_to_string(uidlist->mailbox_guid));
		if (str_len(uidlist->hdr_extensions) > 0) {
			str_append_c(str, ' ');
			str_append_str(str, uidlist->hdr_extensions);
		}
		str_append_c(str, '\n');
		o_stream_nsend(output, str_data(str), str_len(str));
	}

	iter = maildir_uidlist_iter_init(uidlist);
	i_assert(first_idx <= array_count(&uidlist->records));
	iter->next += first_idx;

	while (maildir_uidlist_iter_next_rec(iter, &rec)) {
		uidlist->read_records_count++;
		str_truncate(str, 0);
		str_printfa(str, "%u", rec->uid);
		if (rec->extensions != NULL) {
			for (p = rec->extensions; *p != '\0'; ) {
				i_assert(MAILDIR_UIDLIST_REC_EXT_KEY_IS_VALID(*p));
				len = strlen((const char *)p);
				str_append_c(str, ' ');
				str_append_data(str, p, len);
				p += len + 1;
			}
		}
		str_append(str, " :");
		strp = strchr(rec->filename, *MAILDIR_INFO_SEP_S);
		if (strp == NULL)
			str_append(str, rec->filename);
		else
			str_append_data(str, rec->filename, strp - rec->filename);
		str_append_c(str, '\n');
		o_stream_nsend(output, str_data(str), str_len(str));
	}
	maildir_uidlist_iter_deinit(&iter);

	if (o_stream_finish(output) < 0) {
		mailbox_set_critical(uidlist->box, "write(%s) failed: %s",
				     path, o_stream_get_error(output));
		o_stream_unref(&output);
		return -1;
	}

	*file_size_r = output->offset;
	o_stream_unref(&output);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(fd) < 0) {
			mailbox_set_critical(uidlist->box,
				"fdatasync(%s) failed: %m", path);
			return -1;
		}
	}
	return 0;
}

static void
maildir_uidlist_records_drop_expunges(struct maildir_uidlist *uidlist)
{
	struct mail_index_view *view;
	struct maildir_uidlist_rec *const *recs;
	ARRAY_TYPE(maildir_uidlist_rec_p) new_records;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;
	unsigned int i, count;
	uint32_t seq;

	/* we could get here when opening and locking mailbox,
	   before index files have been opened. */
	if (!uidlist->box->opened)
		return;

	mail_index_refresh(uidlist->box->index);
	view = mail_index_view_open(uidlist->box->index);
	count = array_count(&uidlist->records);
	hdr = mail_index_get_header(view);
	if (count * UIDLIST_COMPRESS_PERCENTAGE / 100 <= hdr->messages_count) {
		/* too much trouble to be worth it */
		mail_index_view_close(&view);
		return;
	}

	i_array_init(&new_records, hdr->messages_count + 64);
	recs = array_get(&uidlist->records, &count);
	for (i = 0, seq = 1; i < count && seq <= hdr->messages_count; ) {
		rec = mail_index_lookup(view, seq);
		if (recs[i]->uid < rec->uid) {
			/* expunged entry */
			hash_table_remove(uidlist->files, recs[i]->filename);
			i++;
		} else if (recs[i]->uid > rec->uid) {
			/* index isn't up to date. we're probably just
			   syncing it here. ignore this entry. */
			seq++;
		} else {
			array_push_back(&new_records, &recs[i]);
			seq++; i++;
		}
	}

	/* drop messages expunged at the end of index */
	while (i < count && recs[i]->uid < hdr->next_uid) {
		hash_table_remove(uidlist->files, recs[i]->filename);
		i++;
	}
	/* view might not be completely up-to-date, so preserve any
	   messages left */
	for (; i < count; i++)
		array_push_back(&new_records, &recs[i]);

	array_free(&uidlist->records);
	uidlist->records = new_records;

	mail_index_view_close(&view);
}

static int maildir_uidlist_recreate(struct maildir_uidlist *uidlist)
{
	struct mailbox *box = uidlist->box;
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	const char *control_dir, *temp_path;
	struct stat st;
	mode_t old_mask;
	uoff_t file_size;
	int i, fd, ret;

	i_assert(uidlist->initial_read);

	maildir_uidlist_records_drop_expunges(uidlist);

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_CONTROL,
				&control_dir) <= 0)
		i_unreached();
	temp_path = t_strconcat(control_dir,
				"/" MAILDIR_UIDLIST_NAME ".tmp", NULL);

	for (i = 0;; i++) {
		old_mask = umask(0777 & ~perm->file_create_mode);
		fd = open(temp_path, O_RDWR | O_CREAT | O_TRUNC, 0777);
		umask(old_mask);
		if (fd != -1)
			break;

		if (errno != ENOENT || i == MAILDIR_DELETE_RETRY_COUNT) {
			mailbox_set_critical(box,
				"open(%s, O_CREAT) failed: %m", temp_path);
			return -1;
		}
		/* the control dir doesn't exist. create it unless the whole
		   mailbox was just deleted. */
		if (!maildir_set_deleted(uidlist->box))
			return -1;
	}

	if (perm->file_create_gid != (gid_t)-1 &&
	    fchown(fd, (uid_t)-1, perm->file_create_gid) < 0) {
		if (errno == EPERM) {
			mailbox_set_critical(box, "%s",
				eperm_error_get_chgrp("fchown", temp_path,
						perm->file_create_gid,
						perm->file_create_gid_origin));
		} else {
			mailbox_set_critical(box,
				"fchown(%s) failed: %m", temp_path);
		}
	}

	uidlist->read_records_count = 0;
	ret = maildir_uidlist_write_fd(uidlist, fd, temp_path, 0, &file_size);
	if (ret == 0) {
		if (rename(temp_path, uidlist->path) < 0) {
			mailbox_set_critical(box,
				"rename(%s, %s) failed: %m",
				temp_path, uidlist->path);
			ret = -1;
		}
	}

	if (ret < 0)
		i_unlink(temp_path);
	else if (fstat(fd, &st) < 0) {
		mailbox_set_critical(box,
			"fstat(%s) failed: %m", temp_path);
		ret = -1;
	} else if (file_size != (uoff_t)st.st_size) {
		i_assert(!file_dotlock_is_locked(uidlist->dotlock));
		mailbox_set_critical(box,
			"Maildir uidlist dotlock overridden: %s",
			uidlist->path);
		ret = -1;
	} else {
		maildir_uidlist_close(uidlist);
		uidlist->fd = fd;
		uidlist->fd_dev = st.st_dev;
		uidlist->fd_ino = st.st_ino;
		uidlist->fd_size = st.st_size;
		uidlist->last_read_offset = st.st_size;
		uidlist->recreate = FALSE;
		uidlist->recreate_on_change = FALSE;
		uidlist->have_mailbox_guid = TRUE;
		maildir_uidlist_update_hdr(uidlist, &st);
	}
	if (ret < 0)
		i_close_fd(&fd);
	return ret;
}

int maildir_uidlist_update(struct maildir_uidlist *uidlist)
{
	int ret;

	if (!uidlist->recreate)
		return 0;

	if (maildir_uidlist_lock(uidlist) <= 0)
		return -1;
	ret = maildir_uidlist_recreate(uidlist);
	maildir_uidlist_unlock(uidlist);
	return ret;
}

static bool maildir_uidlist_want_compress(struct maildir_uidlist_sync_ctx *ctx)
{
	unsigned int min_rewrite_count;

	if (!ctx->uidlist->locked_refresh)
		return FALSE;
	if (ctx->uidlist->recreate)
		return TRUE;

	min_rewrite_count =
		(ctx->uidlist->read_records_count + ctx->new_files_count) *
		UIDLIST_COMPRESS_PERCENTAGE / 100;
	return min_rewrite_count >= array_count(&ctx->uidlist->records);
}

static bool maildir_uidlist_want_recreate(struct maildir_uidlist_sync_ctx *ctx)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;

	if (!uidlist->locked_refresh || !uidlist->initial_read)
		return FALSE;

	if (ctx->finish_change_counter != uidlist->change_counter)
		return TRUE;
	if (uidlist->fd == -1 || uidlist->version != UIDLIST_VERSION ||
	    !uidlist->have_mailbox_guid)
		return TRUE;
	return maildir_uidlist_want_compress(ctx);
}

static int maildir_uidlist_sync_update(struct maildir_uidlist_sync_ctx *ctx)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct stat st;
	uoff_t file_size;

	if (maildir_uidlist_want_recreate(ctx) || uidlist->recreate_on_change)
		return maildir_uidlist_recreate(uidlist);

	if (!uidlist->locked_refresh || uidlist->fd == -1) {
		/* make sure we have the latest file (e.g. NOREFRESH used) */
		i_assert(uidlist->initial_hdr_read);
		if (maildir_uidlist_open_latest(uidlist) < 0)
			return -1;
		if (uidlist->recreate_on_change)
			return maildir_uidlist_recreate(uidlist);
	}
	i_assert(ctx->first_unwritten_pos != UINT_MAX);

	if (lseek(uidlist->fd, 0, SEEK_END) < 0) {
		mailbox_set_critical(uidlist->box,
			"lseek(%s) failed: %m", uidlist->path);
		return -1;
	}

	if (maildir_uidlist_write_fd(uidlist, uidlist->fd, uidlist->path,
				     ctx->first_unwritten_pos, &file_size) < 0)
		return -1;

	if (fstat(uidlist->fd, &st) < 0) {
		mailbox_set_critical(uidlist->box,
			"fstat(%s) failed: %m", uidlist->path);
		return -1;
	}
	if ((uoff_t)st.st_size != file_size) {
		i_warning("%s: file size changed unexpectedly after write",
			  uidlist->path);
	} else if (uidlist->locked_refresh) {
		uidlist->fd_size = st.st_size;
		uidlist->last_read_offset = st.st_size;
		maildir_uidlist_update_hdr(uidlist, &st);
	}
	return 0;
}

static void maildir_uidlist_mark_all(struct maildir_uidlist *uidlist,
				     bool nonsynced)
{
	struct maildir_uidlist_rec **recs;
	unsigned int i, count;

	recs = array_get_modifiable(&uidlist->records, &count);
	if (nonsynced) {
		for (i = 0; i < count; i++)
			recs[i]->flags |= MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	} else {
		for (i = 0; i < count; i++)
			recs[i]->flags &= ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	}
}

static int maildir_uidlist_sync_lock(struct maildir_uidlist *uidlist,
				     enum maildir_uidlist_sync_flags sync_flags,
				     bool *locked_r)
{
	bool nonblock, refresh;
	int ret;

	*locked_r = FALSE;

	if ((sync_flags & MAILDIR_UIDLIST_SYNC_NOLOCK) != 0) {
		if (maildir_uidlist_refresh(uidlist) < 0)
			return -1;
		return 1;
	}

	nonblock = (sync_flags & MAILDIR_UIDLIST_SYNC_TRYLOCK) != 0;
	refresh = (sync_flags & MAILDIR_UIDLIST_SYNC_NOREFRESH) == 0;

	ret = maildir_uidlist_lock_timeout(uidlist, nonblock, refresh, refresh);
	if (ret <= 0) {
		if (ret < 0 || !nonblock)
			return ret;

		/* couldn't lock it */
		if ((sync_flags & MAILDIR_UIDLIST_SYNC_FORCE) == 0)
			return 0;
		/* forcing the sync anyway */
		if (maildir_uidlist_refresh(uidlist) < 0)
			return -1;
	} else {
		*locked_r = TRUE;
	}
	return 1;
}

void maildir_uidlist_set_all_nonsynced(struct maildir_uidlist *uidlist)
{
	maildir_uidlist_mark_all(uidlist, TRUE);
}

int maildir_uidlist_sync_init(struct maildir_uidlist *uidlist,
			      enum maildir_uidlist_sync_flags sync_flags,
			      struct maildir_uidlist_sync_ctx **sync_ctx_r)
{
	struct maildir_uidlist_sync_ctx *ctx;
	bool locked;
	int ret;

	ret = maildir_uidlist_sync_lock(uidlist, sync_flags, &locked);
	if (ret <= 0)
		return ret;

	*sync_ctx_r = ctx = i_new(struct maildir_uidlist_sync_ctx, 1);
	ctx->uidlist = uidlist;
	ctx->sync_flags = sync_flags;
	ctx->partial = !locked ||
		(sync_flags & MAILDIR_UIDLIST_SYNC_PARTIAL) != 0;
	ctx->locked = locked;
	ctx->first_unwritten_pos = UINT_MAX;
	ctx->first_new_pos = UINT_MAX;

	if (ctx->partial) {
		if ((sync_flags & MAILDIR_UIDLIST_SYNC_KEEP_STATE) == 0) {
			/* initially mark all nonsynced */
			maildir_uidlist_mark_all(uidlist, TRUE);
		}
		return 1;
	}
	i_assert(uidlist->locked_refresh);

	ctx->record_pool = pool_alloconly_create(MEMPOOL_GROWING
						 "maildir_uidlist_sync", 16384);
	hash_table_create(&ctx->files, ctx->record_pool, 4096,
			  maildir_filename_base_hash,
			  maildir_filename_base_cmp);

	i_array_init(&ctx->records, array_count(&uidlist->records));
	return 1;
}

static int
maildir_uidlist_sync_next_partial(struct maildir_uidlist_sync_ctx *ctx,
				  const char *filename, uint32_t uid,
				  enum maildir_uidlist_rec_flag flags,
				  struct maildir_uidlist_rec **rec_r)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct maildir_uidlist_rec *rec, *const *recs;
	unsigned int count;

	/* we'll update uidlist directly */
	rec = hash_table_lookup(uidlist->files, filename);
	if (rec == NULL) {
		/* doesn't exist in uidlist */
		if (!ctx->locked) {
			/* we can't add it, so just ignore it */
			return 1;
		}
		if (ctx->first_new_pos == UINT_MAX)
			ctx->first_new_pos = array_count(&uidlist->records);
		ctx->new_files_count++;
		ctx->changed = TRUE;

		if (uidlist->record_pool == NULL) {
			uidlist->record_pool =
				pool_alloconly_create(MEMPOOL_GROWING
						      "uidlist record_pool",
						      1024);
		}

		rec = p_new(uidlist->record_pool,
			    struct maildir_uidlist_rec, 1);
		rec->uid = (uint32_t)-1;
		rec->filename = p_strdup(uidlist->record_pool, filename);
		array_push_back(&uidlist->records, &rec);
		uidlist->change_counter++;

		hash_table_insert(uidlist->files, rec->filename, rec);
	} else if (strcmp(rec->filename, filename) != 0) {
		rec->filename = p_strdup(uidlist->record_pool, filename);
	}
	if (uid != 0) {
		if (rec->uid != uid && rec->uid != (uint32_t)-1) {
			mailbox_set_critical(uidlist->box,
				"Maildir: %s changed UID %u -> %u",
				filename, rec->uid, uid);
			return -1;
		}
		rec->uid = uid;
		if (uidlist->next_uid <= uid)
			uidlist->next_uid = uid + 1;
		else {
			recs = array_get(&uidlist->records, &count);
			if (count > 1 && uid < recs[count-1]->uid)
				uidlist->unsorted = TRUE;
		}
	}

	rec->flags &= ~MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
	rec->flags = (rec->flags | flags) &
		~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;

	ctx->finished = FALSE;
	*rec_r = rec;
	return 1;
}

static unsigned char *ext_dup(pool_t pool, const unsigned char *extensions)
{
	unsigned char *ret;

	if (extensions == NULL)
		return NULL;

	T_BEGIN {
		unsigned int len;

		for (len = 0; extensions[len] != '\0'; len++) {
			while (extensions[len] != '\0') len++;
		}
		ret = p_malloc(pool, len + 1);
		memcpy(ret, extensions, len);
	} T_END;
	return ret;
}

int maildir_uidlist_sync_next(struct maildir_uidlist_sync_ctx *ctx,
			      const char *filename,
			      enum maildir_uidlist_rec_flag flags)
{
	struct maildir_uidlist_rec *rec;

	return maildir_uidlist_sync_next_uid(ctx, filename, 0, flags, &rec);
}

int maildir_uidlist_sync_next_uid(struct maildir_uidlist_sync_ctx *ctx,
				  const char *filename, uint32_t uid,
				  enum maildir_uidlist_rec_flag flags,
				  struct maildir_uidlist_rec **rec_r)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;
	struct maildir_uidlist_rec *rec, *old_rec;
	const char *p;

	*rec_r = NULL;

	if (ctx->failed)
		return -1;
	for (p = filename; *p != '\0'; p++) {
		if (*p == 13 || *p == 10) {
			i_warning("Maildir %s: Ignoring a file with #0x%x: %s",
				  mailbox_get_path(uidlist->box), *p, filename);
			return 1;
		}
	}

	if (ctx->partial) {
		return maildir_uidlist_sync_next_partial(ctx, filename,
							 uid, flags, rec_r);
	}

	rec = hash_table_lookup(ctx->files, filename);
	if (rec != NULL) {
		if ((rec->flags & (MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				   MAILDIR_UIDLIST_REC_FLAG_MOVED)) == 0) {
			/* possibly duplicate */
			return 0;
		}

		/* probably was in new/ and now we're seeing it in cur/.
		   remove new/moved flags so if this happens again we'll know
		   to check for duplicates. */
		rec->flags &= ~(MAILDIR_UIDLIST_REC_FLAG_NEW_DIR |
				MAILDIR_UIDLIST_REC_FLAG_MOVED);
		if (strcmp(rec->filename, filename) != 0)
			rec->filename = p_strdup(ctx->record_pool, filename);
	} else {
		old_rec = hash_table_lookup(uidlist->files, filename);
		i_assert(old_rec != NULL || UIDLIST_IS_LOCKED(uidlist));

		rec = p_new(ctx->record_pool, struct maildir_uidlist_rec, 1);

		if (old_rec != NULL) {
			*rec = *old_rec;
			rec->extensions =
				ext_dup(ctx->record_pool, rec->extensions);
		} else {
			rec->uid = (uint32_t)-1;
			ctx->new_files_count++;
			ctx->changed = TRUE;
			/* didn't exist in uidlist, it's recent */
			flags |= MAILDIR_UIDLIST_REC_FLAG_RECENT;
		}
		rec->filename = p_strdup(ctx->record_pool, filename);
		hash_table_insert(ctx->files, rec->filename, rec);

		array_push_back(&ctx->records, &rec);
	}
	if (uid != 0) {
		rec->uid = uid;
		if (uidlist->next_uid <= uid)
			uidlist->next_uid = uid + 1;
	}

	rec->flags = (rec->flags | flags) & ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	*rec_r = rec;
	return 1;
}

void maildir_uidlist_sync_remove(struct maildir_uidlist_sync_ctx *ctx,
				 const char *filename)
{
	struct maildir_uidlist_rec *rec;
	unsigned int idx;

	i_assert(ctx->partial);
	i_assert(ctx->uidlist->locked_refresh);

	rec = hash_table_lookup(ctx->uidlist->files, filename);
	i_assert(rec != NULL);
	i_assert(rec->uid != (uint32_t)-1);

	hash_table_remove(ctx->uidlist->files, filename);
	idx = maildir_uidlist_records_array_delete(ctx->uidlist, rec);

	if (ctx->first_unwritten_pos != UINT_MAX) {
		i_assert(ctx->first_unwritten_pos > idx);
		ctx->first_unwritten_pos--;
	}
	if (ctx->first_new_pos != UINT_MAX) {
		i_assert(ctx->first_new_pos > idx);
		ctx->first_new_pos--;
	}

	ctx->changed = TRUE;
	ctx->uidlist->recreate = TRUE;
}

void maildir_uidlist_sync_set_ext(struct maildir_uidlist_sync_ctx *ctx,
				  struct maildir_uidlist_rec *rec,
				  enum maildir_uidlist_rec_ext_key key,
				  const char *value)
{
	pool_t pool = ctx->partial ?
		ctx->uidlist->record_pool : ctx->record_pool;

	i_assert(MAILDIR_UIDLIST_REC_EXT_KEY_IS_VALID(key));

	maildir_uidlist_rec_set_ext(rec, pool, key, value);
}

const char *
maildir_uidlist_sync_get_full_filename(struct maildir_uidlist_sync_ctx *ctx,
				       const char *filename)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_table_lookup(ctx->files, filename);
	return rec == NULL ? NULL : rec->filename;
}

bool maildir_uidlist_get_uid(struct maildir_uidlist *uidlist,
			     const char *filename, uint32_t *uid_r)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_table_lookup(uidlist->files, filename);
	if (rec == NULL)
		return FALSE;

	*uid_r = rec->uid;
	return TRUE;
}

void maildir_uidlist_update_fname(struct maildir_uidlist *uidlist,
				  const char *filename)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_table_lookup(uidlist->files, filename);
	if (rec == NULL)
		return;

	rec->flags &= ~MAILDIR_UIDLIST_REC_FLAG_NONSYNCED;
	if (strcmp(rec->filename, filename) != 0)
		rec->filename = p_strdup(uidlist->record_pool, filename);
}

const char *
maildir_uidlist_get_full_filename(struct maildir_uidlist *uidlist,
				  const char *filename)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_table_lookup(uidlist->files, filename);
	return rec == NULL ? NULL : rec->filename;
}

static int maildir_assign_uid_cmp(const void *p1, const void *p2)
{
	const struct maildir_uidlist_rec *const *rec1 = p1, *const *rec2 = p2;

	if ((*rec1)->uid != (*rec2)->uid) {
		if ((*rec1)->uid < (*rec2)->uid)
			return -1;
		else
			return 1;
	}
	return maildir_filename_sort_cmp((*rec1)->filename, (*rec2)->filename);
}

static void maildir_uidlist_assign_uids(struct maildir_uidlist_sync_ctx *ctx)
{
	struct maildir_uidlist_rec **recs;
	unsigned int dest, count;

	i_assert(UIDLIST_IS_LOCKED(ctx->uidlist));
	i_assert(ctx->first_new_pos != UINT_MAX);

	if (ctx->first_unwritten_pos == UINT_MAX)
		ctx->first_unwritten_pos = ctx->first_new_pos;

	/* sort new files and assign UIDs for them */
	recs = array_get_modifiable(&ctx->uidlist->records, &count);
	qsort(recs + ctx->first_new_pos, count - ctx->first_new_pos,
	      sizeof(*recs), maildir_assign_uid_cmp);

	for (dest = ctx->first_new_pos; dest < count; dest++) {
		if (recs[dest]->uid == (uint32_t)-1)
			break;
	}

	for (; dest < count; dest++) {
		i_assert(recs[dest]->uid == (uint32_t)-1);
		i_assert(ctx->uidlist->next_uid < (uint32_t)-1);
		recs[dest]->uid = ctx->uidlist->next_uid++;
		recs[dest]->flags &= ~MAILDIR_UIDLIST_REC_FLAG_MOVED;
	}

	if (ctx->uidlist->locked_refresh && ctx->uidlist->initial_read)
		ctx->uidlist->last_seen_uid = ctx->uidlist->next_uid-1;

	ctx->new_files_count = 0;
	ctx->first_new_pos = UINT_MAX;
	ctx->uidlist->change_counter++;
	ctx->finish_change_counter = ctx->uidlist->change_counter;
}

static void maildir_uidlist_swap(struct maildir_uidlist_sync_ctx *ctx)
{
	struct maildir_uidlist *uidlist = ctx->uidlist;

	/* buffer is unsorted, sort it by UID */
	array_sort(&ctx->records, maildir_uid_cmp);

	array_free(&uidlist->records);
	uidlist->records = ctx->records;
	ctx->records.arr.buffer = NULL;
	i_assert(array_is_created(&uidlist->records));

	hash_table_destroy(&uidlist->files);
	uidlist->files = ctx->files;
	i_zero(&ctx->files);

	pool_unref(&uidlist->record_pool);
	uidlist->record_pool = ctx->record_pool;
	ctx->record_pool = NULL;

	if (ctx->new_files_count != 0) {
		ctx->first_new_pos = array_count(&uidlist->records) -
			ctx->new_files_count;
		maildir_uidlist_assign_uids(ctx);
	} else {
		ctx->uidlist->change_counter++;
	}
}

void maildir_uidlist_sync_recreate(struct maildir_uidlist_sync_ctx *ctx)
{
	ctx->uidlist->recreate = TRUE;
}

void maildir_uidlist_sync_finish(struct maildir_uidlist_sync_ctx *ctx)
{
	if (!ctx->partial) {
		if (!ctx->failed)
			maildir_uidlist_swap(ctx);
	} else {
		if (ctx->new_files_count != 0 && !ctx->failed) {
			i_assert(ctx->changed);
			i_assert(ctx->locked);
			maildir_uidlist_assign_uids(ctx);
		}
	}

	ctx->finished = TRUE;

	/* mbox=NULL means we're coming from dbox rebuilding code.
	   the dbox is already locked, so allow uidlist recreation */
	i_assert(ctx->locked || !ctx->changed);
	if ((ctx->changed || maildir_uidlist_want_compress(ctx)) &&
	    !ctx->failed && ctx->locked) {
		T_BEGIN {
			if (maildir_uidlist_sync_update(ctx) < 0) {
				/* we couldn't write everything we wanted. make
				   sure we don't continue using those UIDs */
				maildir_uidlist_reset(ctx->uidlist);
				ctx->failed = TRUE;
			}
		} T_END;
	}
}

int maildir_uidlist_sync_deinit(struct maildir_uidlist_sync_ctx **_ctx,
				bool success)
{
	struct maildir_uidlist_sync_ctx *ctx = *_ctx;
	int ret;

	*_ctx = NULL;

	if (!success)
		ctx->failed = TRUE;
	ret = ctx->failed ? -1 : 0;

	if (!ctx->finished)
		maildir_uidlist_sync_finish(ctx);
	if (ctx->partial)
		maildir_uidlist_mark_all(ctx->uidlist, FALSE);
	if (ctx->locked)
		maildir_uidlist_unlock(ctx->uidlist);

	if (hash_table_is_created(ctx->files))
		hash_table_destroy(&ctx->files);
	pool_unref(&ctx->record_pool);
	if (array_is_created(&ctx->records))
		array_free(&ctx->records);
	i_free(ctx);
	return ret;
}

void maildir_uidlist_add_flags(struct maildir_uidlist *uidlist,
			       const char *filename,
			       enum maildir_uidlist_rec_flag flags)
{
	struct maildir_uidlist_rec *rec;

	rec = hash_table_lookup(uidlist->files, filename);
	i_assert(rec != NULL);

	rec->flags |= flags;
}

struct maildir_uidlist_iter_ctx *
maildir_uidlist_iter_init(struct maildir_uidlist *uidlist)
{
	struct maildir_uidlist_iter_ctx *ctx;
	unsigned int count;

	ctx = i_new(struct maildir_uidlist_iter_ctx, 1);
	ctx->uidlist = uidlist;
	ctx->next = array_get(&uidlist->records, &count);
	ctx->end = ctx->next + count;
	ctx->change_counter = ctx->uidlist->change_counter;
	return ctx;
}

static void
maildir_uidlist_iter_update_idx(struct maildir_uidlist_iter_ctx *ctx)
{
	unsigned int old_rev_idx, idx, count;

	old_rev_idx = ctx->end - ctx->next;
	ctx->next = array_get(&ctx->uidlist->records, &count);
	ctx->end = ctx->next + count;

	idx = old_rev_idx >= count ? 0 :
		count - old_rev_idx;
	while (idx < count && ctx->next[idx]->uid <= ctx->prev_uid)
		idx++;
	while (idx > 0 && ctx->next[idx-1]->uid > ctx->prev_uid)
		idx--;

	ctx->next += idx;
}

static bool maildir_uidlist_iter_next_rec(struct maildir_uidlist_iter_ctx *ctx,
					  struct maildir_uidlist_rec **rec_r)
{
	struct maildir_uidlist_rec *rec;

	if (ctx->change_counter != ctx->uidlist->change_counter)
		maildir_uidlist_iter_update_idx(ctx);

	if (ctx->next == ctx->end)
		return FALSE;

	rec = *ctx->next;
	i_assert(rec->uid != (uint32_t)-1);

	ctx->prev_uid = rec->uid;
	ctx->next++;

	*rec_r = rec;
	return TRUE;
}

bool maildir_uidlist_iter_next(struct maildir_uidlist_iter_ctx *ctx,
			       uint32_t *uid_r,
			       enum maildir_uidlist_rec_flag *flags_r,
			       const char **filename_r)
{
	struct maildir_uidlist_rec *rec;

	if (!maildir_uidlist_iter_next_rec(ctx, &rec))
		return FALSE;

	*uid_r = rec->uid;
	*flags_r = rec->flags;
	*filename_r = rec->filename;
	return TRUE;
}

void maildir_uidlist_iter_deinit(struct maildir_uidlist_iter_ctx **_ctx)
{
	i_free(*_ctx);
	*_ctx = NULL;
}
