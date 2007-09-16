/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-sync.h"

#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

static int maildir_file_do_try(struct maildir_mailbox *mbox, uint32_t uid,
			       maildir_file_do_func *callback, void *context)
{
	const char *fname, *path;
        enum maildir_uidlist_rec_flag flags;
	int ret;

	fname = maildir_uidlist_lookup(mbox->uidlist, uid, &flags);
	if (fname == NULL)
		return -2; /* expunged */

	t_push();
	if ((flags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(mbox->path, "/new/", fname, NULL);
		ret = callback(mbox, path, context);
		if (ret != 0) {
			t_pop();
			return ret;
		}
	}

	path = t_strconcat(mbox->path, "/cur/", fname, NULL);
	ret = callback(mbox, path, context);
	t_pop();
	return ret;
}

static int do_racecheck(struct maildir_mailbox *mbox, const char *path,
			void *context ATTR_UNUSED)
{
	struct stat st;

	if (lstat(path, &st) == 0 && (st.st_mode & S_IFLNK) != 0) {
		/* most likely a symlink pointing to a non-existing file */
		mail_storage_set_critical(&mbox->storage->storage,
			"Maildir: Symlink destination doesn't exist: %s", path);
		return -2;
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
			"maildir_file_do(%s): Filename keeps changing", path);
		return -1;
	}
}

#undef maildir_file_do
int maildir_file_do(struct maildir_mailbox *mbox, uint32_t uid,
		    maildir_file_do_func *callback, void *context)
{
	int i, ret;

	ret = maildir_file_do_try(mbox, uid, callback, context);
	for (i = 0; i < 10 && ret == 0; i++) {
		/* file is either renamed or deleted. sync the maildir and
		   see which one. if file appears to be renamed constantly,
		   don't try to open it more than 10 times. */
		if (maildir_storage_sync_force(mbox) < 0)
			return -1;

		ret = maildir_file_do_try(mbox, uid, callback, context);
	}

	if (i == 10)
		ret = maildir_file_do_try(mbox, uid, do_racecheck, context);

	return ret == -2 ? 0 : ret;
}

void maildir_tmp_cleanup(struct mail_storage *storage, const char *dir)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	string_t *path;
	unsigned int dir_len;

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
				"opendir(%s) failed: %m", dir);
		}
		return;
	}

	t_push();
	path = t_str_new(256);
	str_printfa(path, "%s/", dir);
	dir_len = str_len(path);

	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.' &&
		    (d->d_name[1] == '\0' ||
		     (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
			/* skip . and .. */
			continue;
		}

		str_truncate(path, dir_len);
		str_append(path, d->d_name);
		if (stat(str_c(path), &st) < 0) {
			if (errno != ENOENT) {
				mail_storage_set_critical(storage,
					"stat(%s) failed: %m", str_c(path));
			}
		} else if (st.st_ctime <=
			   ioloop_time - MAILDIR_TMP_DELETE_SECS) {
			if (unlink(str_c(path)) < 0 && errno != ENOENT) {
				mail_storage_set_critical(storage,
					"unlink(%s) failed: %m", str_c(path));
			}
		}
	}
	t_pop();

#ifdef HAVE_DIRFD
	if (fstat(dirfd(dirp), &st) < 0) {
		mail_storage_set_critical(storage,
			"fstat(%s) failed: %m", dir);
	}
#else
	if (stat(dir, &st) < 0) {
		mail_storage_set_critical(storage,
			"stat(%s) failed: %m", dir);
	}
#endif
	else if (st.st_atime < ioloop_time) {
		/* mounted with noatime. update it ourself. */
		if (utime(dir, NULL) < 0 && errno != ENOENT) {
			mail_storage_set_critical(storage,
				"utime(%s) failed: %m", dir);
		}
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", dir);
	}
}
