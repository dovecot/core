/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "iobuffer.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

static char my_hostdomain[256] = "";

static int write_from_line(MailStorage *storage, int fd, time_t internal_date)
{
	const char *sender, *line, *name;
	size_t len;

	if (*my_hostdomain == '\0') {
		struct hostent *hent;

		hostpid_init();
		hent = gethostbyname(my_hostname);

		name = hent != NULL ? hent->h_name : NULL;
		if (name == NULL) {
			/* failed, use just the hostname */
			name = my_hostname;
		}

		strncpy(my_hostdomain, name, 255);
		my_hostdomain[255] = '\0';
	}

	sender = t_strconcat(storage->user, "@", my_hostdomain, NULL);

	line = mbox_from_create(sender, internal_date);
	len = strlen(line);

	return write_full(fd, line, len) < 0;
}

int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, IOBuffer *data, uoff_t data_size)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	off_t pos;
	int fd, failed;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return FALSE;

	/* append the data into mbox file */
	fd = open(ibox->index->mbox_path, O_RDWR | O_CREAT);
	if (fd == -1) {
		mail_storage_set_critical(box->storage, "Can't open mbox file "
					  "%s: %m", ibox->index->mbox_path);
		return FALSE;
	}

	if (!mbox_lock(ibox->index, ibox->index->mbox_path, fd)) {
		(void)close(fd);
		return mail_storage_set_index_error(ibox);
	}

	failed = FALSE;

	pos = lseek(fd, 0, SEEK_END);
	if (pos == -1) {
		mail_storage_set_critical(box->storage,
					  "lseek() failed for mbox file %s: %m",
					  ibox->index->mbox_path);
		failed = TRUE;
	} else {
		if (pos > 0) {
			/* make sure the file ends with \n */
			if (lseek(fd, 0, pos-1) != pos-1)
				failed = TRUE;
			else {
				char ch;

				if (read(fd, &ch, 1) != 1)
					failed = TRUE;
				else if (ch != '\n') {
					if (write_full(fd, &ch, 1) < 0)
						failed = TRUE;
				}
			}
		}

		if (failed) {
			/* don't bother separating the errors, it's very
			   unlikely that this will happen */
			mail_storage_set_critical(box->storage,
						  "Error appending LF to mbox "
						  "file %s: %m",
						  ibox->index->mbox_path);
		} else if (!write_from_line(box->storage, fd, internal_date) ||
			   !index_storage_save_into_fd(box->storage, fd,
						       ibox->index->mbox_path,
						       data, data_size)) {
			/* failed, truncate file back to original size */
			(void)ftruncate(fd, pos);
			failed = TRUE;
		}
	}

	(void)mbox_unlock(ibox->index, ibox->index->mbox_path, fd);
	(void)close(fd);
	return !failed;
}
