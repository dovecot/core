/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "maildir-index.h"
#include "maildir-uidlist.h"

#include <stdio.h>
#include <sys/stat.h>
#include <utime.h>

/* how many seconds to wait before overriding uidlist.lock */
#define UIDLIST_LOCK_STALE_TIMEOUT (60*5)

int maildir_uidlist_try_lock(struct mail_index *index)
{
	struct stat st;
	const char *path;
	int fd, i;

	i_assert(!INDEX_IS_UIDLIST_LOCKED(index));

	path = t_strconcat(index->control_dir,
			   "/" MAILDIR_UIDLIST_NAME ".lock", NULL);
	for (i = 0; i < 2; i++) {
		fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (fd != -1)
			break;

		if (errno != EEXIST) {
			if (errno == EACCES) {
				/* read-only mailbox */
				return 0;
			}
			index_file_set_syscall_error(index, path, "open()");
			return -1;
		}

		/* exists, is it stale? */
		if (stat(path, &st) < 0) {
			if (errno == ENOENT) {
				/* try again */
				continue;
			}
			index_file_set_syscall_error(index, path, "stat()");
			return -1;
		}

		if (st.st_mtime < ioloop_time - UIDLIST_LOCK_STALE_TIMEOUT) {
			if (unlink(path) < 0 && errno != ENOENT) {
				index_file_set_syscall_error(index, path,
							     "unlink()");
				return -1;
			}
			/* try again */
			continue;
		}
		return 0;
	}

	index->maildir_lock_fd = fd;
	return 1;
}

void maildir_uidlist_unlock(struct mail_index *index)
{
	const char *path;

	if (!INDEX_IS_UIDLIST_LOCKED(index))
		return;

	path = t_strconcat(index->control_dir,
			   "/" MAILDIR_UIDLIST_NAME ".lock", NULL);
	if (unlink(path) < 0 && errno != ENOENT)
		index_file_set_syscall_error(index, path, "unlink()");

	if (close(index->maildir_lock_fd) < 0)
		index_file_set_syscall_error(index, path, "close()");
	index->maildir_lock_fd = -1;
}

struct maildir_uidlist *maildir_uidlist_open(struct mail_index *index)
{
	const char *path, *line;
	struct maildir_uidlist *uidlist;
	unsigned int version;
	int fd;

	path = t_strconcat(index->control_dir, "/" MAILDIR_UIDLIST_NAME, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			index_file_set_syscall_error(index, path, "open()");
		return NULL;
	}

	uidlist = i_new(struct maildir_uidlist, 1);
	uidlist->index = index;
	uidlist->fname = i_strdup(path);
	uidlist->input = i_stream_create_file(fd, default_pool, 4096, TRUE);

	/* get header */
	line = i_stream_read_next_line(uidlist->input);
	if (line == NULL || sscanf(line, "%u %u %u", &version,
				   &uidlist->uid_validity,
				   &uidlist->next_uid) != 3 ||
	    version != 1) {
		/* broken file */
		(void)unlink(path);
		maildir_uidlist_close(uidlist);
		return NULL;
	}

	return uidlist;
}

int maildir_uidlist_next(struct maildir_uidlist *uidlist,
			 struct maildir_uidlist_rec *uid_rec)
{
	const char *line;
	unsigned int uid;

	memset(uid_rec, 0, sizeof(*uid_rec));

	line = i_stream_read_next_line(uidlist->input);
	if (line == NULL)
		return 0;

	uid = 0;
	while (*line >= '0' && *line <= '9') {
		uid = uid*10 + (*line - '0');
		line++;
	}

	if (uid == 0 || *line != ' ') {
		/* invalid file */
		index_set_error(uidlist->index, "Invalid data in file %s",
				uidlist->fname);
		(void)unlink(uidlist->fname);
		return -1;
	}
	if (uid <= uidlist->last_read_uid) {
		index_set_error(uidlist->index,
				"UIDs not ordered in file %s (%u > %u)",
				uidlist->fname, uid, uidlist->last_read_uid);
		(void)unlink(uidlist->fname);
		return -1;
	}
	if (uid >= uidlist->next_uid) {
		index_set_error(uidlist->index,
				"UID larger than next_uid in file %s "
				"(%u >= %u)", uidlist->fname,
				uid, uidlist->next_uid);
		(void)unlink(uidlist->fname);
		return -1;
	}

	while (*line == ' ') line++;

	uid_rec->uid = uid;
	uid_rec->filename = line;
	return 1;
}

void maildir_uidlist_close(struct maildir_uidlist *uidlist)
{
	i_stream_unref(uidlist->input);
	i_free(uidlist->fname);
	i_free(uidlist);
}

static int maildir_uidlist_rewrite_fd(struct mail_index *index,
				      const char *temp_path, time_t *mtime)
{
	struct mail_index_record *rec;
	struct utimbuf ut;
	const char *p, *fname;
	string_t *str;
	size_t len;

	str = t_str_new(4096);
	str_printfa(str, "1 %u %u\n",
		    index->header->uid_validity, index->header->next_uid);

	rec = index->lookup(index, 1);
	while (rec != NULL) {
		fname = maildir_get_location(index, rec);
		if (fname == NULL)
			return FALSE;

		p = strchr(fname, ':');
		len = p == NULL ? strlen(fname) : (size_t)(p-fname);

		if (str_len(str) + MAX_INT_STRLEN + len + 2 >= 4096) {
			/* flush buffer */
			if (write_full(index->maildir_lock_fd,
				       str_data(str), str_len(str)) < 0) {
				index_file_set_syscall_error(index, temp_path,
							     "write_full()");
				return FALSE;
			}
			str_truncate(str, 0);
		}

		str_printfa(str, "%u ", rec->uid);
		str_append_n(str, fname, len);
		str_append_c(str, '\n');

		rec = index->next(index, rec);
	}

	if (write_full(index->maildir_lock_fd,
		       str_data(str), str_len(str)) < 0) {
		index_file_set_syscall_error(index, temp_path, "write_full()");
		return FALSE;
	}

	/* uidlist's mtime must grow every time */
	*mtime = ioloop_time > *mtime ? ioloop_time : *mtime + 1;
	ut.actime = ioloop_time;
	ut.modtime = *mtime;
	if (utime(temp_path, &ut) < 0)
		index_set_syscall_error(index, "utime()");

	if (fsync(index->maildir_lock_fd) < 0) {
		index_file_set_syscall_error(index, temp_path, "fsync()");
		return FALSE;
	}

	return TRUE;
}

int maildir_uidlist_rewrite(struct mail_index *index, time_t *mtime)
{
	const char *temp_path, *db_path;
	int failed = FALSE;

	i_assert(INDEX_IS_UIDLIST_LOCKED(index));

	if (index->lock_type == MAIL_LOCK_UNLOCK) {
		if (!index->set_lock(index, MAIL_LOCK_SHARED))
			return FALSE;
	}

	temp_path = t_strconcat(index->control_dir,
				"/" MAILDIR_UIDLIST_NAME ".lock", NULL);

	failed = !maildir_uidlist_rewrite_fd(index, temp_path, mtime);
	if (close(index->maildir_lock_fd) < 0) {
		index_file_set_syscall_error(index, temp_path, "close()");
		failed = TRUE;
	}
        index->maildir_lock_fd = -1;

	if (!failed) {
		db_path = t_strconcat(index->control_dir,
				      "/" MAILDIR_UIDLIST_NAME, NULL);

		if (rename(temp_path, db_path) < 0) {
			index_set_error(index, "rename(%s, %s) failed: %m",
					temp_path, db_path);
			failed = TRUE;
		}
	}

	if (failed)
		(void)unlink(temp_path);
	return !failed;
}
