/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"
#include "mbox-file.h"
#include "istream-raw-mbox.h"

#include <sys/stat.h>

int mbox_file_open(struct mbox_mailbox *mbox)
{
	struct stat st;
	int fd;

	i_assert(mbox->mbox_fd == -1);

	if (mbox->mbox_file_stream != NULL) {
		/* read-only mbox stream */
		i_assert(mbox->mbox_readonly);
		return 0;
	}

	fd = open(mbox->path, mbox->mbox_readonly ? O_RDONLY : O_RDWR);
	if (fd == -1 && errno == EACCES && !mbox->mbox_readonly) {
                mbox->mbox_readonly = TRUE;
		fd = open(mbox->path, O_RDONLY);
	}

	if (fd == -1) {
		mbox_set_syscall_error(mbox, "open()");
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		mbox_set_syscall_error(mbox, "fstat()");
		(void)close(fd);
		return -1;
	}

	mbox->mbox_writeonly = S_ISFIFO(st.st_mode);
	mbox->mbox_fd = fd;
	mbox->mbox_dev = st.st_dev;
	mbox->mbox_ino = st.st_ino;
	return 0;
}

void mbox_file_close(struct mbox_mailbox *mbox)
{
	mbox_file_close_stream(mbox);

	if (mbox->mbox_fd != -1) {
		if (close(mbox->mbox_fd) < 0)
			i_error("close(mbox) failed: %m");
		mbox->mbox_fd = -1;
	}
}

int mbox_file_open_stream(struct mbox_mailbox *mbox)
{
	if (mbox->mbox_stream != NULL)
		return 0;

	if (mbox->mbox_file_stream != NULL) {
		/* read-only mbox stream */
		i_assert(mbox->mbox_fd == -1 && mbox->mbox_readonly);

		mbox->mbox_stream =
			i_stream_create_raw_mbox(default_pool,
						 mbox->mbox_file_stream);
		return 0;
	}

	if (mbox->mbox_fd == -1) {
		if (mbox_file_open(mbox) < 0)
			return -1;
	}

	if (mbox->mbox_writeonly) {
		mbox->mbox_file_stream =
			i_stream_create_from_data(default_pool, NULL, 0);
	} else if (mbox->ibox.mail_read_mmaped) {
		mbox->mbox_file_stream =
			i_stream_create_mmap(mbox->mbox_fd, default_pool,
					     MAIL_MMAP_BLOCK_SIZE,
					     0, 0, FALSE);
	} else {
		mbox->mbox_file_stream =
			i_stream_create_file(mbox->mbox_fd, default_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}

	mbox->mbox_stream =
		i_stream_create_raw_mbox(default_pool, mbox->mbox_file_stream);
	return 0;
}

void mbox_file_close_stream(struct mbox_mailbox *mbox)
{
	if (mbox->mbox_stream != NULL) {
		i_stream_unref(mbox->mbox_stream);
		mbox->mbox_stream = NULL;
	}

	if (mbox->mbox_file_stream != NULL) {
		if (mbox->mbox_fd == -1) {
			/* read-only mbox stream */
			i_assert(mbox->mbox_readonly);
		} else {
			i_stream_close(mbox->mbox_file_stream);
			i_stream_unref(mbox->mbox_file_stream);
			mbox->mbox_file_stream = NULL;
		}
	}
}

int mbox_file_seek(struct mbox_mailbox *mbox, struct mail_index_view *view,
		   uint32_t seq, int *deleted_r)
{
	const void *data;
	uint64_t offset;
	int ret;

	*deleted_r = FALSE;

	ret = mail_index_lookup_ext(view, seq, mbox->mbox_ext_idx, &data);
	if (ret <= 0) {
		if (ret < 0)
			mail_storage_set_index_error(&mbox->ibox);
		else
			*deleted_r = TRUE;
		return -1;
	}

	if (data == NULL) {
		mail_storage_set_critical(STORAGE(mbox->storage),
			"Cached message offset lost for seq %u in mbox file %s",
			seq, mbox->path);
                mbox->mbox_sync_dirty = TRUE;
		return 0;
	}

	offset = *((const uint64_t *)data);
	if (istream_raw_mbox_seek(mbox->mbox_stream, offset) < 0) {
		if (offset == 0) {
			mail_storage_set_error(STORAGE(mbox->storage),
				"Mailbox isn't a valid mbox file");
			return -1;
		}

		if (mbox->mbox_sync_dirty)
			return 0;

		mail_storage_set_critical(STORAGE(mbox->storage),
			"Cached message offset %s is invalid for mbox file %s",
			dec2str(offset), mbox->path);
		mbox->mbox_sync_dirty = TRUE;
		return 0;
	}

	if (mbox->mbox_sync_dirty) {
		/* we're dirty - make sure this is the correct mail */
		ret = mbox_sync_parse_match_mail(mbox, view, seq);
		if (ret <= 0)
			return ret;

		ret = istream_raw_mbox_seek(mbox->mbox_stream, offset);
		i_assert(ret == 0);
	}

	return 1;
}
