/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

static MailIndexRecord *mail_index_record_append_begin(MailIndex *index,
						       time_t internal_date)
{
	MailIndexRecord trec, *rec;

	memset(&trec, 0, sizeof(MailIndexRecord));
	trec.internal_date = internal_date;

	rec = &trec;
	if (!index->append_begin(index, &rec))
		return NULL;

	return rec;
}

static int maildir_index_append_fd(MailIndex *index, int fd, const char *path,
				   const char *fname)
{
	MailIndexRecord *rec;
	MailIndexUpdate *update;
	struct stat st;
	int failed;

	i_assert(path != NULL);
	i_assert(fname != NULL);

	/* check that file size is somewhat reasonable */
	if (fstat(fd, &st) < 0)
		return index_file_set_syscall_error(index, path, "fstat()");

	if (st.st_size < 10) {
		/* This cannot be a mail file - delete it */
		index_set_error(index, "Invalid size %"PRIuUOFF_T
				" with mail in %s - deleted", st.st_size, path);
		if (unlink(path) < 0)
			index_file_set_syscall_error(index, path, "unlink()");
		return TRUE;
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* append the file into index */
	rec = mail_index_record_append_begin(index, st.st_mtime);
	if (rec == NULL)
		return FALSE;

	/* set message flags from file name */
	rec->msg_flags = maildir_filename_get_flags(fname, 0);
	mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);

	update = index->update_begin(index, rec);

	/* set the location */
	index->update_field(update, FIELD_TYPE_LOCATION, fname,
			    MAILDIR_LOCATION_EXTRA_SPACE);

	/* parse the header and update record's fields */
	failed = !maildir_record_update(index, update, fd);

	if (!index->update_end(update) || failed)
		return FALSE;

	return index->append_end(index, rec);
}

int maildir_index_append_file(MailIndex *index, const char *dir,
			      const char *fname)
{
	const char *path;
	int fd, ret;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	i_assert(dir != NULL);
	i_assert(fname != NULL);

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

	ret = maildir_index_append_fd(index, fd, path, fname);
	if (close(fd) < 0)
		return index_file_set_syscall_error(index, path, "close()");
	return ret;
}

int maildir_index_build_dir(MailIndex *index, const char *source_dir,
			    const char *dest_dir)
{
	DIR *dirp;
	const char *final_dir;
	struct dirent *d;
	struct stat st;
	char sourcepath[1024], destpath[1024];
	int failed;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);
	i_assert(source_dir != NULL);

	dirp = opendir(source_dir);
	if (dirp == NULL) {
		return index_file_set_syscall_error(index, source_dir,
						    "opendir()");
	}

	final_dir = dest_dir != NULL ? dest_dir : source_dir;

	failed = FALSE;
	while (!failed && (d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		if (dest_dir != NULL) {
			/* move the file into dest_dir - abort everything if it
			   already exists, as that should never happen */
			i_snprintf(sourcepath, sizeof(sourcepath), "%s/%s",
				   source_dir, d->d_name);
			i_snprintf(destpath, sizeof(destpath), "%s/%s",
				   dest_dir, d->d_name);
			if (stat(destpath, &st) == 0) {
				index_set_error(index, "Can't move mail %s to "
						"%s: file already exists",
						sourcepath, destpath);
				failed = TRUE;
				break;
			}

			/* race condition here - ignore it as the chance of it
			   happening is pretty much zero */

			if (rename(sourcepath, destpath) < 0) {
				index_set_error(index, "maildir build: "
						"rename(%s, %s) failed: %m",
						sourcepath, destpath);
				failed = TRUE;
				break;
			}
		}

		t_push();
		failed = !maildir_index_append_file(index, final_dir,
						    d->d_name);
		t_pop();
	}

	if (closedir(dirp) < 0)
		index_file_set_syscall_error(index, source_dir, "closedir()");
	return !failed;
}
