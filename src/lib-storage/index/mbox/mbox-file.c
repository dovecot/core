/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"
#include "mbox-file.h"
#include "istream-raw-mbox.h"

#include <sys/stat.h>

int mbox_file_open(struct index_mailbox *ibox)
{
	struct stat st;
	int fd;

	i_assert(ibox->mbox_fd == -1);

	fd = open(ibox->path, ibox->mbox_readonly ? O_RDONLY : O_RDWR);
	if (fd == -1 && errno == EACCES && !ibox->mbox_readonly) {
                ibox->mbox_readonly = TRUE;
		fd = open(ibox->path, O_RDONLY);
	}

	if (fd == -1) {
		mbox_set_syscall_error(ibox, "open()");
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		mbox_set_syscall_error(ibox, "fstat()");
		(void)close(fd);
		return -1;
	}

	ibox->mbox_writeonly = S_ISFIFO(st.st_mode);
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

	if (ibox->mbox_writeonly) {
		ibox->mbox_file_stream =
			i_stream_create_from_data(default_pool, NULL, 0);
	} else if (ibox->mail_read_mmaped) {
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

int mbox_file_seek(struct index_mailbox *ibox, struct mail_index_view *view,
		   uint32_t seq, int *deleted_r)
{
	const void *data;
	uint64_t offset;
	int ret;

	*deleted_r = FALSE;

	ret = mail_index_lookup_ext(view, seq, ibox->mbox_ext_idx, &data);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(ibox);
		else
			*deleted_r = TRUE;
		return -1;
	}

	if (data == NULL) {
		mail_storage_set_critical(ibox->box.storage,
			"Cached message offset lost for seq %u in mbox file %s",
			seq, ibox->path);
		mail_index_mark_corrupted(ibox->index);
		return -1;
	}

	offset = *((const uint64_t *)data);
	if (istream_raw_mbox_seek(ibox->mbox_stream, offset) < 0) {
		if (offset == 0) {
			mail_storage_set_error(ibox->box.storage,
				"Mailbox isn't a valid mbox file");
			return -1;
		}

		if (ibox->mbox_sync_dirty)
			return 0;

		mail_storage_set_critical(ibox->box.storage,
			"Cached message offset %s is invalid for mbox file %s",
			dec2str(offset), ibox->path);
		mail_index_mark_corrupted(ibox->index);
		return -1;
	}

	if (ibox->mbox_sync_dirty) {
		/* we're dirty - make sure this is the correct mail */
		ret = mbox_sync_parse_match_mail(ibox, view, seq);
		if (ret <= 0)
			return ret;

		ret = istream_raw_mbox_seek(ibox->mbox_stream, offset);
		i_assert(ret == 0);
	}

	return 1;
}
