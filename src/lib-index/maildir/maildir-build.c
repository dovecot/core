/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "str.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

static int maildir_record_update(struct mail_index *index,
				 struct mail_index_update *update, int fd)
{
	struct istream *input;
        enum mail_data_field cache_fields;

	if (index->mail_read_mmaped) {
		input = i_stream_create_mmap(fd, system_pool,
					     MAIL_MMAP_BLOCK_SIZE, 0, 0, FALSE);
	} else {
		input = i_stream_create_file(fd, system_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}

	cache_fields = index->header->cache_fields & ~DATA_FIELD_LOCATION;
	mail_index_update_headers(update, input, cache_fields, NULL, NULL);

	i_stream_unref(input);
	return TRUE;
}

static int maildir_index_append_fd(struct mail_index *index,
				   int fd, const char *fname)
{
	struct mail_index_record *rec;
	struct mail_index_update *update;
	struct stat st;
	uoff_t virtual_size;
	const char *p;
	int failed;

	i_assert(fname != NULL);

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	rec = index->append_begin(index);
	if (rec == NULL)
		return FALSE;

	/* set message flags from file name */
	rec->msg_flags = maildir_filename_get_flags(fname, 0);
	mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);

	update = index->update_begin(index, rec);

	/* set virtual size if found from file name */
	p = strstr(fname, ",W=");
	if (p != NULL) {
		p += 3;
		virtual_size = 0;
		while (*p >= '0' && *p <= '9') {
			virtual_size = virtual_size * 10 + (*p - '0');
			p++;
		}

		if (*p == ':' || *p == ',' || *p == '\0') {
			index->update_field_raw(update, DATA_HDR_VIRTUAL_SIZE,
						&virtual_size,
						sizeof(virtual_size));
		}
	}

	/* set internal date */
	if (fd != -1 && fstat(fd, &st) == 0) {
		index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
					&st.st_mtime, sizeof(st.st_mtime));
	}

	/* set the location */
	index->update_field(update, DATA_FIELD_LOCATION, fname,
			    MAILDIR_LOCATION_EXTRA_SPACE);

	/* parse the header and update record's fields */
	failed = fd == -1 ? FALSE : !maildir_record_update(index, update, fd);

	if (!index->update_end(update) || failed) {
		index->append_abort(index, rec);
		return FALSE;
	}

	return index->append_end(index, rec);
}

int maildir_index_append_file(struct mail_index *index, const char *dir,
			      const char *fname)
{
	const char *path;
	int fd, ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if ((index->header->cache_fields & ~DATA_FIELD_LOCATION) == 0) {
		/* nothing cached, don't bother opening the file */
		return maildir_index_append_fd(index, -1, fname);
	}

	path = t_strconcat(dir, "/", fname, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		/* open() failed - treat it as error unless the error was
		   "file doesn't exist" in which case someone just managed
		   to delete it before we saw it */
		if (errno == EEXIST)
			return TRUE;

		return index_file_set_syscall_error(index, path, "open()");
	}

	ret = maildir_index_append_fd(index, fd, fname);
	if (close(fd) < 0)
		return index_file_set_syscall_error(index, path, "close()");
	return ret;
}

int maildir_index_build_dir(struct mail_index *index,
			    const char *source_dir, const char *dest_dir,
			    DIR *dirp, struct dirent *d)
{
	const char *final_dir;
	string_t *sourcepath, *destpath;
	int failed;

	i_assert(index->maildir_lock_fd != -1);
	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	sourcepath = t_str_new(PATH_MAX);
	destpath = t_str_new(PATH_MAX);

	final_dir = dest_dir != NULL ? dest_dir : source_dir;

	failed = FALSE;
	for (; d != NULL && !failed; d = readdir(dirp)) {
		if (d->d_name[0] == '.')
			continue;

		if (dest_dir != NULL) {
			/* rename() has the problem that it might overwrite
			   some mails, but that happens only with a broken
			   client that has created non-unique base name.

			   Alternative would be link() + unlink(), but that's
			   racy when multiple clients try to move the mail from
			   new/ to cur/:

			   a) One of the clients uses slightly different
			   filename (eg. sets flags)

			   b) Third client changes mail's flag between
			   client1's unlink() and client2's link() calls.

			   Checking first if file exists with stat() is pretty
			   useless as well. It requires that we also stat the
			   file in new/, to make sure that the dest file isn't
			   actually the same file which someone _just_ had
			   rename()d. */
			str_truncate(sourcepath, 0);
			str_truncate(destpath, 0);

			str_printfa(sourcepath, "%s/%s", source_dir, d->d_name);
			str_printfa(destpath, "%s/%s", dest_dir, d->d_name);

			if (rename(str_c(sourcepath), str_c(destpath)) < 0 &&
			    errno != ENOENT) {
				index_set_error(index, "maildir build: "
						"rename(%s, %s) failed: %m",
						str_c(sourcepath),
						str_c(destpath));
				failed = TRUE;
				break;
			}
		}

		t_push();
		failed = !maildir_index_append_file(index, final_dir,
						    d->d_name);
		t_pop();
	}

	return !failed;
}
