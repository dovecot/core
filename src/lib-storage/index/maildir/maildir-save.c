/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "iobuffer.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>

static int maildir_create_tmp(MailStorage *storage, const char *dir,
			      const char **fname)
{
	static unsigned int create_count = 0;
	const char *path;
	int fd;

	hostpid_init();

	*fname = t_strdup_printf("%lu.%s_%u.%s", (unsigned long) ioloop_time,
				 my_pid, create_count++, my_hostname);

	path = t_strconcat(dir, "/", *fname, NULL);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0660);
	if (fd == -1) {
		/* don't bother checking if it was because file existed -
		   if that happens it's itself an error. */
		mail_storage_set_critical(storage,
					  "Can't create file %s: %m", path);
	}

	return fd;
}

static const char *maildir_read_into_tmp(MailStorage *storage, const char *dir,
					 IOBuffer *buf, size_t data_size)
{
	const char *fname, *path;
	int fd;

	fd = maildir_create_tmp(storage, dir, &fname);
	if (fd == -1)
		return NULL;

	path = t_strconcat(dir, "/", fname, NULL);
	if (!index_storage_save_into_fd(storage, fd, path, buf, data_size))
		fname = NULL;

	(void)close(fd);

	if (fname == NULL)
		(void)unlink(path);
	return fname;
}

int maildir_storage_save(Mailbox *box, MailFlags flags,
			 const char *custom_flags[], time_t internal_date,
			 IOBuffer *data, size_t data_size)
{
        IndexMailbox *ibox = (IndexMailbox *) box;
        struct utimbuf buf;
	const char *tmpdir, *fname, *tmp_path, *new_path;
	int failed;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return mail_storage_set_index_error(ibox);

	t_push();

	/* create the file into tmp/ directory */
	tmpdir = t_strconcat(ibox->index->dir, "/tmp", NULL);
	fname = maildir_read_into_tmp(box->storage, tmpdir, data, data_size);
	if (fname == NULL) {
		t_pop();
		return FALSE;
	}
	tmp_path = t_strconcat(tmpdir, "/", fname, NULL);

	fname = maildir_filename_set_flags(fname, flags);
	new_path = t_strconcat(ibox->index->dir, "/new/", fname, NULL);

	/* set the internal_date by modifying mtime */
	buf.actime = ioloop_time;
	buf.modtime = internal_date;
	(void)utime(tmp_path, &buf);

	/* move the file into new/ directory - syncing will pick it
	   up from there */
	if (rename(tmp_path, new_path) == 0)
		failed = FALSE;
	else {
		mail_storage_set_critical(box->storage, "rename(%s, %s) "
					  "failed: %m", tmp_path, new_path);
		(void)unlink(tmp_path);
		failed = TRUE;
	}

	t_pop();
	return !failed;
}
