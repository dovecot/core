/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "iobuffer.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mbox-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int mbox_storage_save(Mailbox *box, MailFlags flags, const char *custom_flags[],
		      time_t internal_date, IOBuffer *data, size_t data_size)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	off_t pos;
	int fd, failed;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_mailbox_fix_custom_flags(ibox, &flags, custom_flags))
		return mail_storage_set_index_error(ibox);

	/* append the data into mbox file */
	fd = open(ibox->index->mbox_path, O_RDWR | O_CREAT);
	if (fd == -1) {
		mail_storage_set_error(box->storage, "Can't open mbox file "
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
		mail_storage_set_error(box->storage, "lseek() failed for mbox "
				       "file %s: %m", ibox->index->mbox_path);
		failed = TRUE;
	}

	if (!failed && !index_storage_save_into_fd(box->storage, fd,
						   ibox->index->mbox_path,
						   data, data_size)) {
		/* failed, truncate file back to original size */
		(void)ftruncate(fd, pos);
		failed = TRUE;
	}

	(void)mbox_unlock(ibox->index, ibox->index->mbox_path, fd);
	(void)close(fd);
	return !failed;
}
