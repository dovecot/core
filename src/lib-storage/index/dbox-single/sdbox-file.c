/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "fdatasync-path.h"
#include "mkdir-parents.h"
#include "istream.h"
#include "ostream.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"

#include <stdio.h>

static void sdbox_file_init_paths(struct sdbox_file *file, const char *fname)
{
	struct mailbox *box = &file->mbox->box;
	const char *alt_path;

	i_free(file->file.primary_path);
	i_free(file->file.alt_path);
	file->file.primary_path =
		i_strdup_printf("%s/%s", box->path, fname);

	alt_path = mailbox_list_get_path(box->list, box->name,
					 MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX);
	if (alt_path != NULL)
		file->file.alt_path = i_strdup_printf("%s/%s", alt_path, fname);
}

struct dbox_file *sdbox_file_init(struct sdbox_mailbox *mbox, uint32_t uid)
{
	struct sdbox_file *file;
	const char *fname;

	file = i_new(struct sdbox_file, 1);
	file->file.storage = &mbox->storage->storage;
	file->mbox = mbox;
	T_BEGIN {
		if (uid != 0) {
			fname = t_strdup_printf(SDBOX_MAIL_FILE_FORMAT, uid);
			sdbox_file_init_paths(file, fname);
			file->uid = uid;
		} else {
			file->file.primary_path =
				i_strdup_printf("%s/%s",
						file->mbox->box.path,
						dbox_generate_tmp_filename());
		}
	} T_END;
	dbox_file_init(&file->file);
	return &file->file;
}

struct dbox_file *sdbox_file_create(struct sdbox_mailbox *mbox)
{
	struct dbox_file *file;

	file = sdbox_file_init(mbox, 0);
	file->fd = file->storage->v.
		file_create_fd(file, file->primary_path, FALSE);
	return file;
}

int sdbox_file_assign_uid(struct sdbox_file *file, uint32_t uid)
{
	const char *old_path, *new_fname, *new_path;

	i_assert(file->uid == 0);
	i_assert(uid != 0);

	old_path = file->file.cur_path;
	new_fname = t_strdup_printf(SDBOX_MAIL_FILE_FORMAT, uid);
	new_path = t_strdup_printf("%s/%s", file->mbox->box.path,
				   new_fname);
	if (rename(old_path, new_path) < 0) {
		mail_storage_set_critical(&file->file.storage->storage,
					  "rename(%s, %s) failed: %m",
					  old_path, new_path);
		return -1;
	}
	sdbox_file_init_paths(file, new_fname);
	file->uid = uid;
	return 0;
}

int sdbox_file_create_fd(struct dbox_file *file, const char *path, bool parents)
{
	struct sdbox_file *sfile = (struct sdbox_file *)file;
	struct mailbox *box = &sfile->mbox->box;
	const char *p, *dir;
	mode_t old_mask;
	int fd;

	old_mask = umask(0666 & ~box->file_create_mode);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	umask(old_mask);
	if (fd == -1 && errno == ENOENT && parents &&
	    (p = strrchr(path, '/')) != NULL) {
		dir = t_strdup_until(path, p);
		if (mkdir_parents_chgrp(dir, box->dir_create_mode,
					box->file_create_gid,
					box->file_create_gid_origin) < 0) {
			mail_storage_set_critical(box->storage,
				"mkdir_parents(%s) failed: %m", dir);
			return -1;
		}
		/* try again */
		old_mask = umask(0666 & ~box->file_create_mode);
		fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		umask(old_mask);
	}
	if (fd == -1) {
		mail_storage_set_critical(box->storage,
			"open(%s, O_CREAT) failed: %m", path);
	} else if (box->file_create_gid == (gid_t)-1) {
		/* no group change */
	} else if (fchown(fd, (uid_t)-1, box->file_create_gid) < 0) {
		if (errno == EPERM) {
			mail_storage_set_critical(box->storage, "%s",
				eperm_error_get_chgrp("fchown", path,
					box->file_create_gid,
					box->file_create_gid_origin));
		} else {
			mail_storage_set_critical(box->storage,
				"fchown(%s, -1, %ld) failed: %m",
				path, (long)box->file_create_gid);
		}
		/* continue anyway */
	}
	return fd;
}

int sdbox_file_move(struct dbox_file *file, bool alt_path)
{
	struct mail_storage *storage = &file->storage->storage;
	struct ostream *output;
	const char *dest_dir, *temp_path, *dest_path, *p;
	struct stat st;
	bool deleted;
	int out_fd, ret = 0;

	i_assert(file->input != NULL);

	if (dbox_file_is_in_alt(file) == alt_path)
		return 0;

	if (stat(file->cur_path, &st) < 0 && errno == ENOENT) {
		/* already expunged/moved by another session */
		return 0;
	}

	dest_path = !alt_path ? file->primary_path : file->alt_path;
	p = strrchr(dest_path, '/');
	i_assert(p != NULL);
	dest_dir = t_strdup_until(dest_path, p);
	temp_path = t_strdup_printf("%s/%s", dest_dir,
				    dbox_generate_tmp_filename());

	/* first copy the file. make sure to catch every possible error
	   since we really don't want to break the file. */
	out_fd = file->storage->v.file_create_fd(file, temp_path, TRUE);
	if (out_fd == -1)
		return -1;

	output = o_stream_create_fd_file(out_fd, 0, FALSE);
	i_stream_seek(file->input, 0);
	while ((ret = o_stream_send_istream(output, file->input)) > 0) ;
	if (ret == 0)
		ret = o_stream_flush(output);
	if (output->stream_errno != 0) {
		errno = output->stream_errno;
		mail_storage_set_critical(storage, "write(%s) failed: %m",
					  temp_path);
		ret = -1;
	} else if (file->input->stream_errno != 0) {
		errno = file->input->stream_errno;
		dbox_file_set_syscall_error(file, "ftruncate()");
		ret = -1;
	} else if (ret < 0) {
		mail_storage_set_critical(storage,
			"o_stream_send_istream(%s, %s) "
			"failed with unknown error",
			temp_path, file->cur_path);
	}
	o_stream_unref(&output);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER && ret == 0) {
		if (fsync(out_fd) < 0) {
			mail_storage_set_critical(storage,
				"fsync(%s) failed: %m", temp_path);
			ret = -1;
		}
	}
	if (close(out_fd) < 0) {
		mail_storage_set_critical(storage,
			"close(%s) failed: %m", temp_path);
		ret = -1;
	}
	if (ret < 0) {
		(void)unlink(temp_path);
		return -1;
	}

	/* the temp file was successfully written. rename it now to the
	   destination file. the destination shouldn't exist, but if it does
	   its contents should be the same (except for maybe older metadata) */
	if (rename(temp_path, dest_path) < 0) {
		mail_storage_set_critical(storage,
			"rename(%s, %s) failed: %m", temp_path, dest_path);
		(void)unlink(temp_path);
		return -1;
	}
	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync_path(dest_dir) < 0) {
			mail_storage_set_critical(storage,
				"fdatasync(%s) failed: %m", dest_dir);
			(void)unlink(dest_path);
			return -1;
		}
	}
	if (unlink(file->cur_path) < 0) {
		dbox_file_set_syscall_error(file, "unlink()");
		if (errno == EACCES) {
			/* configuration problem? revert the write */
			(void)unlink(dest_path);
		}
		/* who knows what happened to the file. keep both just to be
		   sure both won't get deleted. */
		return -1;
	}

	/* file was successfully moved - reopen it */
	dbox_file_close(file);
	if (dbox_file_open(file, &deleted) <= 0) {
		mail_storage_set_critical(storage,
			"dbox_file_move(%s): reopening file failed", dest_path);
		return -1;
	}
	return 0;
}
