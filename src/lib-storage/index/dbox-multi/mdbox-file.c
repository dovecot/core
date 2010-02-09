/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-dec.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "mkdir-parents.h"
#include "fdatasync-path.h"
#include "eacces-error.h"
#include "str.h"
#include "mdbox-storage.h"
#include "mdbox-map-private.h"
#include "mdbox-file.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

static struct mdbox_file *
mdbox_find_and_move_open_file(struct mdbox_storage *storage, uint32_t file_id)
{
	struct mdbox_file *const *files, *file;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id == file_id) {
			/* move to last in the array */
			file = files[i];
			array_delete(&storage->open_files, i, 1);
			array_append(&storage->open_files, &file, 1);
			return file;
		}
	}
	return NULL;
}

void mdbox_files_free(struct mdbox_storage *storage)
{
	struct mdbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++)
		dbox_file_free(&files[i]->file);
	array_clear(&storage->open_files);
}

void mdbox_files_sync_input(struct mdbox_storage *storage)
{
	struct mdbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file.input != NULL)
			i_stream_sync(files[i]->file.input);
	}
}

static void
mdbox_close_open_files(struct mdbox_storage *storage, unsigned int close_count)
{
	struct mdbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count;) {
		if (files[i]->file.refcount == 0) {
			dbox_file_free(&files[i]->file);
			array_delete(&storage->open_files, i, 1);

			if (--close_count == 0)
				break;

			files = array_get(&storage->open_files, &count);
		} else {
			i++;
		}
	}
}

static void mdbox_file_init_paths(struct mdbox_file *file, const char *fname)
{
	i_free(file->file.primary_path);
	i_free(file->file.alt_path);
	file->file.primary_path =
		i_strdup_printf("%s/%s", file->storage->storage_dir, fname);
	if (file->storage->alt_storage_dir != NULL) {
		file->file.alt_path =
			i_strdup_printf("%s/%s", file->storage->alt_storage_dir,
					fname);
	}
	file->file.cur_path = file->file.primary_path;
}

static int mdbox_file_create(struct dbox_file *file)
{
	bool create_parents;

	create_parents = dbox_file_is_in_alt(file);
	file->fd = file->storage->v.
		file_create_fd(file, file->cur_path, create_parents);
	return file->fd == -1 ? -1 : 0;
}

static struct dbox_file *
mdbox_file_init_full(struct mdbox_storage *storage,
		     uint32_t file_id, bool alt_dir)
{
	struct mdbox_file *file;
	const char *fname;
	unsigned int count;

	file = file_id == 0 ? NULL :
		mdbox_find_and_move_open_file(storage, file_id);
	if (file != NULL) {
		file->file.refcount++;
		return &file->file;
	}

	count = array_count(&storage->open_files);
	if (count > storage->set->mdbox_max_open_files) {
		mdbox_close_open_files(storage, count -
				       storage->set->mdbox_max_open_files);
	}

	file = i_new(struct mdbox_file, 1);
	file->storage = storage;
	file->file.storage = &storage->storage;
	file->file_id = file_id;
	fname = file_id == 0 ? dbox_generate_tmp_filename() :
		t_strdup_printf(MDBOX_MAIL_FILE_FORMAT, file_id);
	mdbox_file_init_paths(file, fname);
	dbox_file_init(&file->file);
	if (alt_dir)
		file->file.cur_path = file->file.alt_path;

	if (file_id != 0)
		array_append(&storage->open_files, &file, 1);
	else
		(void)mdbox_file_create(&file->file);
	return &file->file;
}

struct dbox_file *
mdbox_file_init(struct mdbox_storage *storage, uint32_t file_id)
{
	return mdbox_file_init_full(storage, file_id, FALSE);
}

struct dbox_file *
mdbox_file_init_new_alt(struct mdbox_storage *storage)
{
	return mdbox_file_init_full(storage, 0, TRUE);
}

int mdbox_file_assign_file_id(struct mdbox_file *file, uint32_t file_id)
{
	const char *old_path;
	const char *new_dir, *new_fname, *new_path;

	i_assert(file->file_id == 0);
	i_assert(file_id != 0);

	old_path = file->file.cur_path;
	new_fname = t_strdup_printf(MDBOX_MAIL_FILE_FORMAT, file_id);
	new_dir = !dbox_file_is_in_alt(&file->file) ?
		file->storage->storage_dir : file->storage->alt_storage_dir;
	new_path = t_strdup_printf("%s/%s", new_dir, new_fname);
	if (rename(old_path, new_path) < 0) {
		mail_storage_set_critical(&file->storage->storage.storage,
					  "rename(%s, %s) failed: %m",
					  old_path, new_path);
		return -1;
	}
	mdbox_file_init_paths(file, new_fname);
	file->file_id = file_id;
	array_append(&file->storage->open_files, &file, 1);
	return 0;
}

void mdbox_file_unrefed(struct dbox_file *file)
{
	struct mdbox_file *mfile = (struct mdbox_file *)file;
	struct mdbox_file *const *files, *oldest_file;
	unsigned int i, count;

	/* don't cache metadata seeks while file isn't being referenced */
	file->metadata_read_offset = (uoff_t)-1;

	if (mfile->file_id != 0) {
		files = array_get(&mfile->storage->open_files, &count);
		if (!file->deleted &&
		    count <= mfile->storage->set->mdbox_max_open_files) {
			/* we can leave this file open for now */
			return;
		}

		/* close the oldest file with refcount=0 */
		for (i = 0; i < count; i++) {
			if (files[i]->file.refcount == 0)
				break;
		}
		oldest_file = files[i];
		array_delete(&mfile->storage->open_files, i, 1);
		if (oldest_file != mfile) {
			dbox_file_free(&oldest_file->file);
			return;
		}
		/* have to close ourself */
	}
	dbox_file_free(file);
}

int mdbox_file_create_fd(struct dbox_file *file, const char *path, bool parents)
{
	struct mdbox_file *mfile = (struct mdbox_file *)file;
	struct dbox_map *map = mfile->storage->map;
	mode_t old_mask;
	const char *p, *dir;
	int fd;

	old_mask = umask(0666 & ~map->create_mode);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	umask(old_mask);
	if (fd == -1 && errno == ENOENT && parents &&
	    (p = strrchr(path, '/')) != NULL) {
		dir = t_strdup_until(path, p);
		if (mkdir_parents_chgrp(dir, map->create_dir_mode,
					map->create_gid,
					map->create_gid_origin) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"mkdir_parents(%s) failed: %m", dir);
			return -1;
		}
		/* try again */
		old_mask = umask(0666 & ~map->create_mode);
		fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		umask(old_mask);
	}
	if (fd == -1) {
		mail_storage_set_critical(&file->storage->storage,
			"open(%s, O_CREAT) failed: %m", path);
	} else if (map->create_gid == (gid_t)-1) {
		/* no group change */
	} else if (fchown(fd, (uid_t)-1, map->create_gid) < 0) {
		if (errno == EPERM) {
			mail_storage_set_critical(&file->storage->storage, "%s",
				eperm_error_get_chgrp("fchown", path,
						      map->create_gid,
						      map->create_gid_origin));
		} else {
			mail_storage_set_critical(&file->storage->storage,
				"fchown(%s, -1, %ld) failed: %m",
				path, (long)map->create_gid);
		}
		/* continue anyway */
	}
	return fd;
}
