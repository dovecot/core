/* Copyright (c) 2004-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"
#include "maildir-sync.h"

#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/stat.h>

#define MAILDIR_RESYNC_RETRY_COUNT 10

static const char *
maildir_filename_guess(struct maildir_mailbox *mbox, uint32_t uid,
		       const char *fname, bool *have_flags_r)

{
	struct mail_index_view *view = mbox->flags_view;
	struct maildir_keywords_sync_ctx *kw_ctx;
	enum mail_flags flags;
	ARRAY_TYPE(keyword_indexes) keywords;
	uint32_t seq;

	if (view == NULL || !mail_index_lookup_seq(view, uid, &seq)) {
		*have_flags_r = FALSE;
		return fname;
	}

	t_array_init(&keywords, 32);
	mail_index_lookup_view_flags(view, seq, &flags, &keywords);
	if (array_count(&keywords) == 0) {
		*have_flags_r = (flags & MAIL_FLAGS_NONRECENT) != 0;
		fname = maildir_filename_set_flags(NULL, fname, flags, NULL);
	} else {
		*have_flags_r = TRUE;
		kw_ctx = maildir_keywords_sync_init_readonly(mbox->keywords,
							     mbox->ibox.index);
		fname = maildir_filename_set_flags(kw_ctx, fname,
						   flags, &keywords);
		maildir_keywords_sync_deinit(&kw_ctx);
	}
	return fname;
}

static int maildir_file_do_try(struct maildir_mailbox *mbox, uint32_t uid,
			       maildir_file_do_func *callback, void *context)
{
	const char *path, *fname;
	enum maildir_uidlist_rec_flag flags;
	bool have_flags;
	int ret;

	ret = maildir_uidlist_lookup(mbox->uidlist, uid, &flags, &fname);
	if (ret <= 0)
		return ret == 0 ? -2 : -1;

	if ((flags & MAILDIR_UIDLIST_REC_FLAG_NONSYNCED) != 0) {
		/* let's see if we can guess the filename based on index */
		fname = maildir_filename_guess(mbox, uid, fname, &have_flags);
		if (have_flags) {
			/* don't even bother looking into new/ dir */
			flags &= MAILDIR_UIDLIST_REC_FLAG_NEW_DIR;
		}
	}

	if ((flags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(mbox->path, "/new/", fname, NULL);
		ret = callback(mbox, path, context);
		if (ret != 0)
			return ret;
	}

	path = t_strconcat(mbox->path, "/cur/", fname, NULL);
	ret = callback(mbox, path, context);
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

	T_BEGIN {
		ret = maildir_file_do_try(mbox, uid, callback, context);
	} T_END;
	for (i = 0; i < MAILDIR_RESYNC_RETRY_COUNT && ret == 0; i++) {
		/* file is either renamed or deleted. sync the maildir and
		   see which one. if file appears to be renamed constantly,
		   don't try to open it more than 10 times. */
		if (maildir_storage_sync_force(mbox, uid) < 0)
			return -1;

		T_BEGIN {
			ret = maildir_file_do_try(mbox, uid, callback, context);
		} T_END;
	}

	if (i == MAILDIR_RESYNC_RETRY_COUNT) T_BEGIN {
		ret = maildir_file_do_try(mbox, uid, do_racecheck, context);
	} T_END;

	return ret == -2 ? 0 : ret;
}

static int maildir_create_subdirs(struct maildir_mailbox *mbox)
{
	static const char *subdirs[] = { "cur", "new", "tmp" };
	const char *dirs[N_ELEMENTS(subdirs) + 2];
	struct mailbox *box = &mbox->ibox.box;
	struct stat st;
	const char *path;
	unsigned int i;

	/* @UNSAFE: get a list of directories we want to create */
	for (i = 0; i < N_ELEMENTS(subdirs); i++)
		dirs[i] = t_strconcat(mbox->path, "/", subdirs[i], NULL);
	dirs[i++] = mail_storage_get_mailbox_control_dir(box->storage,
							 box->name);
	dirs[i++] = mail_storage_get_mailbox_index_dir(box->storage,
						       box->name);
	i_assert(i == N_ELEMENTS(dirs));

	for (i = 0; i < N_ELEMENTS(dirs); i++) {
		path = dirs[i];
		if (path == NULL || stat(path, &st) == 0)
			continue;
		if (errno != ENOENT) {
			mail_storage_set_critical(box->storage,
						  "stat(%s) failed: %m", path);
			break;
		}
		if (mkdir_parents_chown(path, box->dir_create_mode,
					(uid_t)-1, box->file_create_gid) < 0 &&
		    errno != EEXIST) {
			if (errno == ENOENT) {
				/* mailbox was being deleted just now */
				mailbox_set_deleted(box);
				break;
			}
			mail_storage_set_critical(box->storage,
						  "mkdir(%s) failed: %m", path);
			break;
		}
	}
	return i == N_ELEMENTS(dirs) ? 0 : -1;
}

bool maildir_set_deleted(struct maildir_mailbox *mbox)
{
	struct mailbox *box = &mbox->ibox.box;
	struct stat st;
	int ret;

	if (stat(mbox->path, &st) < 0) {
		if (errno == ENOENT)
			mailbox_set_deleted(box);
		else {
			mail_storage_set_critical(box->storage,
				"stat(%s) failed: %m", mbox->path);
		}
		return FALSE;
	}
	/* maildir itself exists. create all of its subdirectories in case
	   they got lost. */
	T_BEGIN {
		ret = maildir_create_subdirs(mbox);
	} T_END;
	return ret < 0 ? FALSE : TRUE;
}
