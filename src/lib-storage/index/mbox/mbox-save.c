/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "ibuffer.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

static char my_hostdomain[256] = "";

static int set_error(MailStorage *storage, const char *mbox_path)
{
	if (errno == ENOSPC)
		mail_storage_set_error(storage, "Not enough disk space");
	else {
		mail_storage_set_critical(storage, "Error writing to "
					  "mbox file %s: %m", mbox_path);
	}

	return FALSE;
}

static int mbox_check_ending_lf(MailStorage *storage, int fd, off_t pos,
				const char *mbox_path)
{
	char ch;

	if (pos == 0)
		return TRUE;

	do {
		if (lseek(fd, pos-1, SEEK_SET) < 0)
			break;

		if (read(fd, &ch, 1) != 1)
			break;

		if (ch != '\n') {
			if (write_full(fd, "\n", 1) < 0)
				break;
		}

		return TRUE;
	} while (0);

	return set_error(storage, mbox_path);
}

static int mbox_append_lf(MailStorage *storage, int fd, const char *mbox_path)
{
	if (write_full(fd, "\n", 1) < 0)
		return set_error(storage, mbox_path);

	return TRUE;
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

	if (write_full(fd, line, len) < 0)
		return set_error(storage, mbox_path);

	return TRUE;
}

static int write_flags(MailStorage *storage, int fd, const char *mbox_path,
		       MailFlags flags, const char *custom_flags[])
{
	const char *str;
	unsigned int field;
	int i;

	if (flags == 0)
		return TRUE;

	if (flags & MAIL_SEEN) {
		if (write_full(fd, "Status: R\n", 10) < 0)
			return set_error(storage, mbox_path);
	}

	if (flags & (MAIL_ANSWERED|MAIL_DRAFT|MAIL_FLAGGED|MAIL_DELETED)) {
		str = t_strconcat("X-Status: ",
				  (flags & MAIL_ANSWERED) ? "A" : "",
				  (flags & MAIL_DRAFT) ? "D" : "",
				  (flags & MAIL_FLAGGED) ? "F" : "",
				  (flags & MAIL_DELETED) ? "T" : "",
				  "\n", NULL);

		if (write_full(fd, str, strlen(str)) < 0)
			return set_error(storage, mbox_path);
	}

	if (flags & MAIL_CUSTOM_FLAGS_MASK) {
		if (write_full(fd, "X-Keywords:", 11) < 0)
			return set_error(storage, mbox_path);

		field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
		for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, field <<= 1) {
			if ((flags & field) && custom_flags[i] != NULL) {
				if (write_full(fd, " ", 1) < 0)
					return set_error(storage, mbox_path);

				if (write_full(fd, custom_flags[i],
					       strlen(custom_flags[i])) < 0)
					return set_error(storage, mbox_path);
			}
		}

		if (write_full(fd, "\n", 1) < 0)
			return set_error(storage, mbox_path);
	}

	return TRUE;
}

int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, IBuffer *data, uoff_t data_size)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	MailFlags real_flags;
	const char *mbox_path;
	IBuffer *inbuf;
	int fd, failed;
	off_t pos;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	/* we don't need the real flags, easier to keep using our own.
	   they need to be checked/added though. */
	real_flags = flags;
	if (!index_mailbox_fix_custom_flags(ibox, &real_flags, custom_flags))
		return FALSE;

	/* just make sure the mbox is opened, we don't need the ibuffer */
	inbuf = mbox_file_open(ibox->index, 0, TRUE);
	if (inbuf == NULL)
		return FALSE;

	i_buffer_unref(inbuf);
	fd = ibox->index->mbox_fd;

	if (!mbox_lock_write(ibox->index)) {
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
		    !write_flags(box->storage, fd, mbox_path, flags,
				 custom_flags) ||
		    !index_storage_save_into_fd(box->storage, fd, mbox_path,
						data, data_size) ||
		    !mbox_append_lf(box->storage, fd, mbox_path)) {
			/* failed, truncate file back to original size */
			(void)ftruncate(fd, pos);
			failed = TRUE;
		}
	}

	(void)mbox_unlock(ibox->index);
	return !failed;
}
