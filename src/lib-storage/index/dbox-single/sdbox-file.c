/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"

#include <stdio.h>

static void sdbox_file_init_paths(struct sdbox_file *file, const char *fname)
{
	i_free(file->file.primary_path);
	i_free(file->file.alt_path);
	file->file.primary_path =
		i_strdup_printf("%s/%s", file->mbox->ibox.box.path, fname);
	if (file->mbox->alt_path != NULL) {
		file->file.alt_path =
			i_strdup_printf("%s/%s", file->mbox->alt_path, fname);
	}
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
						file->mbox->ibox.box.path,
						dbox_generate_tmp_filename());
		}
	} T_END;
	dbox_file_init(&file->file);

	if (uid == 0) {
		file->file.fd = file->file.storage->v.
			file_create_fd(&file->file, file->file.primary_path,
				       FALSE);
	}
	return &file->file;
}

int sdbox_file_assign_uid(struct sdbox_file *file, uint32_t uid)
{
	const char *old_path, *new_fname, *new_path;

	i_assert(file->uid == 0);
	i_assert(uid != 0);

	old_path = file->file.cur_path;
	new_fname = t_strdup_printf(SDBOX_MAIL_FILE_FORMAT, uid);
	new_path = t_strdup_printf("%s/%s", file->mbox->ibox.box.path,
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
	struct mailbox *box = &sfile->mbox->ibox.box;
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
