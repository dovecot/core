/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "istream-raw-mbox.h"

#include <sys/stat.h>

int mbox_file_open(struct index_mailbox *ibox)
{
	struct stat st;
	int fd;

	i_assert(ibox->mbox_fd == -1);

	fd = open(ibox->path, ibox->readonly ? O_RDONLY : O_RDWR);
	if (fd == -1) {
		mbox_set_syscall_error(ibox, "open()");
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		mbox_set_syscall_error(ibox, "fstat()");
		(void)close(fd);
		return -1;
	}

	ibox->mbox_fd = fd;
	ibox->mbox_dev = st.st_dev;
	ibox->mbox_ino = st.st_ino;
	return 0;
}

void mbox_file_close(struct index_mailbox *ibox)
{
	mbox_file_close_stream(ibox);

	if (ibox->mbox_fd != -1) {
		if (close(ibox->mbox_fd) < 0)
			i_error("close(mbox) failed: %m");
		ibox->mbox_fd = -1;
	}
}

int mbox_file_open_stream(struct index_mailbox *ibox)
{
	if (ibox->mbox_stream != NULL)
		return 0;

	i_assert(ibox->mbox_file_stream == NULL);

	if (ibox->mbox_fd == -1) {
		if (mbox_file_open(ibox) < 0)
			return -1;
	}

	if (ibox->mail_read_mmaped) {
		ibox->mbox_file_stream =
			i_stream_create_mmap(ibox->mbox_fd, default_pool,
					     MAIL_MMAP_BLOCK_SIZE,
					     0, 0, FALSE);
	} else {
		ibox->mbox_file_stream =
			i_stream_create_file(ibox->mbox_fd, default_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}

	ibox->mbox_stream =
		i_stream_create_raw_mbox(default_pool, ibox->mbox_file_stream);
	return 0;
}

void mbox_file_close_stream(struct index_mailbox *ibox)
{
	if (ibox->mbox_stream != NULL) {
		i_stream_close(ibox->mbox_file_stream);
		i_stream_unref(ibox->mbox_file_stream);
		ibox->mbox_file_stream = NULL;

		i_stream_unref(ibox->mbox_stream);
		ibox->mbox_stream = NULL;
	}
}
