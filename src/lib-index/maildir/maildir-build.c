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

static int maildir_index_append_fd(MailIndex *index, int fd, const char *fname)
{
	MailIndexRecord *rec;
	MailIndexUpdate *update;
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

	ret = maildir_index_append_fd(index, fd, fname);
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
