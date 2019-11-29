/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fs-sis-common.h"

#include <sys/stat.h>

int fs_sis_path_parse(struct fs_file *file, const char *path,
		      const char **dir_r, const char **hash_r)
{
	const char *fname, *p;

	fname = strrchr(path, '/');
	if (fname == NULL) {
		*dir_r = ".";
		fname = path;
	} else {
		*dir_r = t_strdup_until(path, fname);
		fname++;
	}

	/* assume filename begins with "<hash>-" */
	p = strchr(fname, '-');
	if (p == NULL) {
		fs_set_error(file->event, "open(%s) failed: "
			     "Filenames must begin with '<hash>-'", path);
		return -1;
	}
	*hash_r = t_strdup_until(fname, p);
	return 0;
}

void fs_sis_try_unlink_hash_file(struct fs_file *sis_file,
				 struct fs_file *super_file)
{
	struct fs_file *hash_file;
	struct stat st1, st2;
	const char *dir, *hash, *hash_path;

	if (fs_sis_path_parse(sis_file, super_file->path, &dir, &hash) == 0 &&
	    fs_stat(super_file, &st1) == 0 && st1.st_nlink == 2) {
		/* this may be the last link. if hashes/ file is the same,
		   delete it. */
		hash_path = t_strdup_printf("%s/"HASH_DIR_NAME"/%s", dir, hash);
		hash_file = fs_file_init_with_event(super_file->fs,
						    super_file->event, hash_path,
						    FS_OPEN_MODE_READONLY);
		if (fs_stat(hash_file, &st2) == 0 &&
		    st1.st_ino == st2.st_ino &&
		    CMP_DEV_T(st1.st_dev, st2.st_dev)) {
			if (fs_delete(hash_file) < 0) {
				e_error(hash_file->event, "%s",
					fs_file_last_error(hash_file));
			}
		}
		fs_file_deinit(&hash_file);
	}
}

