/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fs-sis-common.h"

#include <sys/stat.h>

int fs_sis_path_parse(struct fs *fs, const char *path,
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
		fs_set_error(fs, "open(%s) failed: "
			     "Filenames must begin with '<hash>-'", path);
		return -1;
	}
	*hash_r = t_strdup_until(fname, p);
	return 0;
}

void fs_sis_try_unlink_hash_file(struct fs *fs, struct fs *super,
				 const char *path)
{
	struct stat st1, st2;
	const char *dir, *hash, *hash_path, *hash_dir;

	if (fs_sis_path_parse(fs, path, &dir, &hash) == 0 &&
	    fs_stat(super, path, &st1) == 0 && st1.st_nlink == 2) {
		/* this may be the last link. if hashes/ file is the same,
		   delete it. */
		hash_path = t_strdup_printf("%s/"HASH_DIR_NAME"/%s", dir, hash);
		if (fs_stat(super, hash_path, &st2) == 0 &&
		    st1.st_ino == st2.st_ino &&
		    CMP_DEV_T(st1.st_dev, st2.st_dev)) {
			if (fs_unlink(super, hash_path) < 0)
				i_error("%s", fs_last_error(super));
			else {
				/* try to rmdir the hashes/ directory */
				hash_dir = t_strdup_printf("%s/"HASH_DIR_NAME,
							   dir);
				(void)fs_rmdir(super, hash_dir);
			}
		}
	}
}

