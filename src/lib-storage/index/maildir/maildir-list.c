/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <dirent.h>
#include <sys/stat.h>

struct find_subscribed_context {
	mailbox_list_callback_t *callback;
	void *context;
};

static enum mailbox_flags
maildir_get_marked_flags_from(const char *dir, time_t index_stamp)
{
	struct stat st;
	char path[PATH_MAX];
	time_t cur_stamp;

	if (str_path(path, sizeof(path), dir, "cur") < 0 ||
	    stat(path, &st) < 0) {
		/* no cur/ directory - broken */
		return 0;
	}

	cur_stamp = st.st_mtime;
	if (cur_stamp != index_stamp) {
		/* changes in cur directory */
		return MAILBOX_MARKED;
	}

	if (str_path(path, sizeof(path), dir, "new") < 0 ||
	    stat(path, &st) < 0) {
		/* no new/ directory - broken */
		return 0;
	}

	return st.st_mtime <= cur_stamp ? MAILBOX_UNMARKED : MAILBOX_MARKED;
}

static enum mailbox_flags
maildir_get_marked_flags(struct mail_storage *storage, const char *dir)
{
	const char *path;
	struct stat st;

	hostpid_init();

	/* first try to use .imap.index-hostname */
	path = t_strconcat(dir, "/" INDEX_FILE_PREFIX "-", my_hostname, NULL);
	if (stat(path, &st) == -1 && errno == ENOENT) {
		/* fallback to .imap.index */
		path = t_strconcat(dir, "/" INDEX_FILE_PREFIX, NULL);
	}

	if (stat(path, &st) == -1) {
		/* error, or index simply isn't created yet */
		if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", path);
		}
		return 0;
	}

	return maildir_get_marked_flags_from(dir, st.st_mtime);
}

int maildir_find_mailboxes(struct mail_storage *storage, const char *mask,
			   mailbox_list_callback_t callback, void *context)
{
        struct imap_match_glob *glob;
	DIR *dirp;
	struct dirent *d;
	struct stat st;
        enum mailbox_flags flags;
	char path[PATH_MAX];
	int failed, found_inbox;

	mail_storage_clear_error(storage);

	dirp = opendir(storage->dir);
	if (dirp == NULL) {
		mail_storage_set_critical(storage, "opendir(%s) failed: %m",
					  storage->dir);
		return FALSE;
	}

	glob = imap_match_init(mask, TRUE, '.');

	failed = found_inbox = FALSE;
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		if (fname[0] != '.')
			continue;

		/* skip . and .. */
		if (fname[1] == '\0' || (fname[1] == '.' && fname[2] == '\0'))
			continue;

		/* make sure the mask matches - dirs beginning with ".."
		   should be deleted and we always want to check those. */
		if (fname[1] == '.' || imap_match(glob, fname+1) <= 0)
			continue;

		if (str_path(path, sizeof(path), storage->dir, fname) < 0)
			continue;

		/* make sure it's a directory */
		if (stat(path, &st) != 0) {
			if (errno == ENOENT)
				continue; /* just deleted, ignore */

			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m", path);
			failed = TRUE;
			break;
		}

		if (!S_ISDIR(st.st_mode))
			continue;

		if (fname[1] == '.') {
			/* this mailbox is in the middle of being deleted,
			   or the process trying to delete it had died.

			   delete it ourself if it's been there longer than
			   one hour */
			if (st.st_mtime < 3600)
				(void)unlink_directory(path, TRUE);
			continue;
		}

		if (strcasecmp(fname+1, "INBOX") == 0)
			found_inbox = TRUE;

		t_push();
		flags = maildir_get_marked_flags(storage, path);
		callback(storage, fname+1, flags, context);
		t_pop();
	}

	if (!failed && !found_inbox && imap_match(glob, "INBOX") > 0) {
		/* .INBOX directory doesn't exist yet, but INBOX still exists */
		callback(storage, "INBOX", 0, context);
	}

	(void)closedir(dirp);
	return !failed;
}

static int maildir_subs_cb(struct mail_storage *storage, const char *name,
			   void *context)
{
	struct find_subscribed_context *ctx = context;
	enum mailbox_flags flags;
	struct stat st;
	char path[PATH_MAX];

	if (str_ppath(path, sizeof(path), storage->dir, ".", name) < 0)
		flags = MAILBOX_NOSELECT;
	else {
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
			flags = maildir_get_marked_flags(storage, path);
		else
			flags = MAILBOX_NOSELECT;
	}

	ctx->callback(storage, name, flags, ctx->context);
	return TRUE;
}

int maildir_find_subscribed(struct mail_storage *storage, const char *mask,
			    mailbox_list_callback_t callback, void *context)
{
	struct find_subscribed_context ctx;

	ctx.callback = callback;
	ctx.context = context;

	if (subsfile_foreach(storage, mask, maildir_subs_cb, &ctx) <= 0)
		return FALSE;

	return TRUE;
}
