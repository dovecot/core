/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"
#include "mbox-file.h"
#include "istream-raw-mbox.h"

#include <sys/stat.h>
#include <utime.h>

#define MBOX_READ_BLOCK_SIZE IO_BLOCK_SIZE

int mbox_file_open(struct mbox_mailbox *mbox)
{
	struct stat st;
	int fd;

	i_assert(mbox->mbox_fd == -1);

	if (mbox->mbox_file_stream != NULL) {
		/* read-only mbox stream */
		i_assert(mbox->box.backend_readonly);
		return 0;
	}

	fd = open(mbox->box.path,
		  mbox->box.backend_readonly ? O_RDONLY : O_RDWR);
	if (fd == -1 && errno == EACCES && !mbox->box.backend_readonly) {
                mbox->box.backend_readonly = TRUE;
		fd = open(mbox->box.path, O_RDONLY);
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
			mbox_set_syscall_error(mbox, "close()");
		mbox->mbox_fd = -1;
	}
}

int mbox_file_open_stream(struct mbox_mailbox *mbox)
{
	if (mbox->mbox_stream != NULL)
		return 0;

	if (mbox->mbox_file_stream != NULL) {
		/* read-only mbox stream */
		i_assert(mbox->mbox_fd == -1 && mbox->box.backend_readonly);
	} else {
		if (mbox->mbox_fd == -1) {
			if (mbox_file_open(mbox) < 0)
				return -1;
		}

		if (mbox->mbox_writeonly) {
			mbox->mbox_file_stream =
				i_stream_create_from_data(NULL, 0);
		} else {
			mbox->mbox_file_stream =
				i_stream_create_fd(mbox->mbox_fd,
						   MBOX_READ_BLOCK_SIZE,
						   FALSE);
			i_stream_set_init_buffer_size(mbox->mbox_file_stream,
						      MBOX_READ_BLOCK_SIZE);
		}
		i_stream_set_name(mbox->mbox_file_stream, mbox->box.path);
	}

	mbox->mbox_stream = i_stream_create_raw_mbox(mbox->mbox_file_stream);
	if (mbox->mbox_lock_type != F_UNLCK)
		istream_raw_mbox_set_locked(mbox->mbox_stream);
	return 0;
}

static void mbox_file_fix_atime(struct mbox_mailbox *mbox)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	struct utimbuf buf;
	struct stat st;

	if (ibox->recent_flags_count > 0 &&
	    (mbox->box.flags & MAILBOX_FLAG_KEEP_RECENT) != 0 &&
	    mbox->mbox_fd != -1 && !mbox->box.backend_readonly) {
		/* we've seen recent messages which we want to keep recent.
		   keep file's atime lower than mtime so \Marked status
		   gets shown while listing */
		if (fstat(mbox->mbox_fd, &st) < 0) {
			mbox_set_syscall_error(mbox, "fstat()");
			return;
		}
		if (st.st_atime >= st.st_mtime) {
			buf.modtime = st.st_mtime;
			buf.actime = buf.modtime - 1;
			/* EPERM can happen with shared mailboxes */
			if (utime(mbox->box.path, &buf) < 0 && errno != EPERM)
				mbox_set_syscall_error(mbox, "utime()");
		}
	}
}
void mbox_file_close_stream(struct mbox_mailbox *mbox)
{
	/* if we read anything, fix the atime if needed */
	mbox_file_fix_atime(mbox);

	if (mbox->mbox_stream != NULL)
		i_stream_destroy(&mbox->mbox_stream);

	if (mbox->mbox_file_stream != NULL) {
		if (mbox->mbox_fd == -1) {
			/* read-only mbox stream */
			i_assert(mbox->box.backend_readonly);
			i_stream_seek(mbox->mbox_file_stream, 0);
		} else {
			i_stream_destroy(&mbox->mbox_file_stream);
		}
	}
}

int mbox_file_lookup_offset(struct mbox_mailbox *mbox,
			    struct mail_index_view *view,
			    uint32_t seq, uoff_t *offset_r)
{
	const void *data;
	bool deleted;

	mail_index_lookup_ext(view, seq, mbox->mbox_ext_idx, &data, &deleted);
	if (deleted)
		return -1;

	if (data == NULL) {
		mail_storage_set_critical(&mbox->storage->storage,
			"Cached message offset lost for seq %u in mbox file %s",
			seq, mbox->box.path);
                mbox->mbox_hdr.dirty_flag = TRUE;
                mbox->mbox_broken_offsets = TRUE;
		return 0;
	}

	*offset_r = *((const uint64_t *)data);
	return 1;
}

int mbox_file_seek(struct mbox_mailbox *mbox, struct mail_index_view *view,
		   uint32_t seq, bool *deleted_r)
{
	uoff_t offset;
	int ret;

	ret = mbox_file_lookup_offset(mbox, view, seq, &offset);
	if (ret <= 0) {
		*deleted_r = ret < 0;
		return ret;
	}
	*deleted_r = FALSE;

	if (istream_raw_mbox_seek(mbox->mbox_stream, offset) < 0) {
		if (offset == 0) {
			mbox->invalid_mbox_file = TRUE;
			mail_storage_set_error(&mbox->storage->storage,
				MAIL_ERROR_NOTPOSSIBLE,
				"Mailbox isn't a valid mbox file");
			return -1;
		}

		if (mbox->mbox_hdr.dirty_flag)
			return 0;

		mail_storage_set_critical(&mbox->storage->storage,
			"Cached message offset %s is invalid for mbox file %s",
			dec2str(offset), mbox->box.path);
		mbox->mbox_hdr.dirty_flag = TRUE;
		mbox->mbox_broken_offsets = TRUE;
		return 0;
	}

	if (mbox->mbox_hdr.dirty_flag) {
		/* we're dirty - make sure this is the correct mail */
		if (!mbox_sync_parse_match_mail(mbox, view, seq))
			return 0;

		ret = istream_raw_mbox_seek(mbox->mbox_stream, offset);
		i_assert(ret == 0);
	}

	return 1;
}
