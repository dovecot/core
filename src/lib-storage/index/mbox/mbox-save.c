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

static void set_error(MailStorage *storage, const char *mbox_path)
{
	if (errno == ENOSPC)
		mail_storage_set_error(storage, "Not enough disk space");
	else {
		mail_storage_set_critical(storage, "Error writing to "
					  "mbox file %s: %m", mbox_path);
	}
}

static int mbox_check_ending_lf(MailStorage *storage, int fd, off_t pos,
				const char *mbox_path)
{
	char ch;

	if (pos == 0)
		return TRUE;

	do {
		if (lseek(fd, 0, pos-1) < 0)
			break;

		if (read(fd, &ch, 1) != 1)
			break;

		if (ch != '\n') {
			if (write_full(fd, &ch, 1) < 0)
				break;
		}

		return TRUE;
	} while (0);

	set_error(storage, mbox_path);
	return FALSE;
}

static int write_from_line(MailStorage *storage, int fd, const char *mbox_path,
			   time_t internal_date)
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

	if (write_full(fd, line, len) < 0) {
		set_error(storage, mbox_path);
		return FALSE;
	}

	return TRUE;
}

int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, IOBuffer *data, uoff_t data_size)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	off_t pos;
	const char *mbox_path;
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
	if (pos < 0) {
		mail_storage_set_critical(box->storage,
					  "lseek() failed for mbox file %s: %m",
					  ibox->index->mbox_path);
		failed = TRUE;
	} else {
		mbox_path = ibox->index->mbox_path;

		if (!mbox_check_ending_lf(box->storage, fd, pos, mbox_path) ||
		    !write_from_line(box->storage, fd, mbox_path,
				     internal_date) ||
		    !index_storage_save_into_fd(box->storage, fd, mbox_path,
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
