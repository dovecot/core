/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "maildir-index.h"
#include "maildir-storage.h"

#include <dirent.h>
#include <sys/stat.h>

typedef struct {
	MailboxFunc func;
	void *context;
} FindSubscribedContext;

static MailboxFlags maildir_get_marked_flags(const char *dir)
{
	struct stat st;
	char path[1024];
	time_t index_stamp, cur_stamp;

	i_snprintf(path, sizeof(path), "%s/" INDEX_FILE_PREFIX, dir);
	if (stat(path, &st) == -1) {
		/* index file wasn't found. it might be with another name,
		   but finding it would be too slow. */
		return 0;
	}

	index_stamp = st.st_mtime;

	i_snprintf(path, sizeof(path), "%s/cur", dir);
	if (stat(path, &st) == -1) {
		/* no cur/ directory - broken */
		return 0;
	}

	cur_stamp = st.st_mtime;
	if (cur_stamp != index_stamp) {
		/* changes in cur directory */
		return MAILBOX_MARKED;
	}

	i_snprintf(path, sizeof(path), "%s/new", dir);
	if (stat(path, &st) == -1) {
		/* no new/ directory - broken */
		return 0;
	}

	return st.st_mtime <= cur_stamp ? MAILBOX_UNMARKED : MAILBOX_MARKED;
}

int maildir_find_mailboxes(MailStorage *storage, const char *mask,
			   MailboxFunc func, void *context)
{
        const ImapMatchGlob *glob;
	DIR *dirp;
	struct dirent *d;
	struct stat st;
        MailboxFlags flags;
	char path[1024];
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
		if (fname[1] == '.' || imap_match(glob, fname+1, 0, NULL) < 0)
			continue;

		/* make sure it's a directory */
		i_snprintf(path, sizeof(path), "%s/%s", storage->dir, fname);
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
				(void)unlink_directory(path);
			continue;
		}

                flags = maildir_get_marked_flags(path);
		func(storage, fname+1, flags, context);
	}

	if (!failed && !found_inbox &&
	    imap_match(glob, "INBOX", 0, NULL) >= 0) {
		/* .INBOX directory doesn't exist yet, but INBOX still exists */
		func(storage, "INBOX", 0, context);
	}

	(void)closedir(dirp);
	return !failed;
}

static int maildir_subs_func(MailStorage *storage, const char *name,
			     void *context)
{
	FindSubscribedContext *ctx = context;
	MailboxFlags flags;
	struct stat st;
	char path[1024];

	i_snprintf(path, sizeof(path), "%s/.%s", storage->dir, name);

	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
		flags = maildir_get_marked_flags(path);
	else
		flags = MAILBOX_NOSELECT;

	ctx->func(storage, name, flags, ctx->context);
	return TRUE;
}

int maildir_find_subscribed(MailStorage *storage, const char *mask,
			    MailboxFunc func, void *context)
{
	FindSubscribedContext ctx;

	ctx.func = func;
	ctx.context = context;

	if (subsfile_foreach(storage, mask, maildir_subs_func, &ctx) <= 0)
		return FALSE;

	return TRUE;
}
