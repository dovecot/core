/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "obuffer.h"
#include "write-full.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netdb.h>

static char my_hostdomain[256] = "";

static int write_error(MailStorage *storage, const char *mbox_path)
{
	if (errno == ENOSPC)
		mail_storage_set_error(storage, "Not enough disk space");
	else {
		mail_storage_set_critical(storage,
			"Error writing to mbox file %s: %m", mbox_path);
	}

	return FALSE;
}

static int mbox_seek_to_end(MailStorage *storage, int fd,
			    const char *mbox_path, off_t *pos)
{
	struct stat st;
	char ch;

	if (fstat(fd, &st) < 0) {
		mail_storage_set_critical(storage,
			"fstat() failed for mbox file %s: %m", mbox_path);
		return FALSE;
	}

	*pos = st.st_size;
	if (st.st_size == 0)
		return TRUE;

	if (lseek(fd, st.st_size-1, SEEK_SET) < 0) {
		mail_storage_set_critical(storage,
			"lseek() failed for mbox file %s: %m", mbox_path);
		return FALSE;
	}

	if (read(fd, &ch, 1) != 1) {
		mail_storage_set_critical(storage,
			"read() failed for mbox file %s: %m", mbox_path);
		return FALSE;
	}

	if (ch != '\n') {
		if (write_full(fd, "\n", 1) < 0)
			return write_error(storage, mbox_path);
		*pos += 1;
	}

	return TRUE;
}

static int mbox_append_lf(MailStorage *storage, OBuffer *outbuf,
			  const char *mbox_path)
{
	if (o_buffer_send(outbuf, "\n", 1) < 0)
		return write_error(storage, mbox_path);

	return TRUE;
}

static int write_from_line(MailStorage *storage, OBuffer *outbuf,
			   const char *mbox_path, time_t internal_date)
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

	/* save in local timezone, no matter what it was given with */
	line = mbox_from_create(sender, internal_date);
	len = strlen(line);

	if (o_buffer_send(outbuf, line, len) < 0)
		return write_error(storage, mbox_path);

	return TRUE;
}

static int write_flags(MailStorage *storage, OBuffer *outbuf,
		       const char *mbox_path,
		       MailFlags flags, const char *custom_flags[])
{
	const char *str;
	unsigned int field;
	int i;

	if (flags == 0)
		return TRUE;

	if (flags & MAIL_SEEN) {
		if (o_buffer_send(outbuf, "Status: R\n", 10) < 0)
			return write_error(storage, mbox_path);
	}

	if (flags & (MAIL_ANSWERED|MAIL_DRAFT|MAIL_FLAGGED|MAIL_DELETED)) {
		str = t_strconcat("X-Status: ",
				  (flags & MAIL_ANSWERED) ? "A" : "",
				  (flags & MAIL_DRAFT) ? "D" : "",
				  (flags & MAIL_FLAGGED) ? "F" : "",
				  (flags & MAIL_DELETED) ? "T" : "",
				  "\n", NULL);

		if (o_buffer_send(outbuf, str, strlen(str)) < 0)
			return write_error(storage, mbox_path);
	}

	if (flags & MAIL_CUSTOM_FLAGS_MASK) {
		if (o_buffer_send(outbuf, "X-Keywords:", 11) < 0)
			return write_error(storage, mbox_path);

		field = 1 << MAIL_CUSTOM_FLAG_1_BIT;
		for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, field <<= 1) {
			if ((flags & field) && custom_flags[i] != NULL) {
				if (o_buffer_send(outbuf, " ", 1) < 0)
					return write_error(storage, mbox_path);

				if (o_buffer_send(outbuf, custom_flags[i],
						  strlen(custom_flags[i])) < 0)
					return write_error(storage, mbox_path);
			}
		}

		if (o_buffer_send(outbuf, "\n", 1) < 0)
			return write_error(storage, mbox_path);
	}

	return TRUE;
}

int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, int timezone_offset __attr_unused__,
		      IBuffer *data, uoff_t data_size)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	MailIndex *index;
	MailFlags real_flags;
	const char *mbox_path;
	OBuffer *outbuf;
	int failed;
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

	if (!index_storage_sync_and_lock(ibox, FALSE, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	index = ibox->index;
	mbox_path = index->mbox_path;
	if (!mbox_seek_to_end(box->storage, index->mbox_fd, mbox_path, &pos))
		failed = TRUE;
	else {
		failed = FALSE;

		t_push();
		outbuf = o_buffer_create_file(index->mbox_fd,
					      data_stack_pool, 4096,
					      0, FALSE);

		if (!write_from_line(box->storage, outbuf, mbox_path,
				     internal_date) ||
		    !write_flags(box->storage, outbuf, mbox_path, flags,
				 custom_flags) ||
		    !index_storage_save(box->storage, mbox_path,
					data, outbuf, data_size) ||
		    !mbox_append_lf(box->storage, outbuf, mbox_path)) {
			/* failed, truncate file back to original size */
			(void)ftruncate(index->mbox_fd, pos);
			failed = TRUE;
		}
		o_buffer_unref(outbuf);
		t_pop();
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return !failed;
}
