/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "mbox-index.h"
#include "mbox-storage.h"
#include "home-expand.h"

#include <dirent.h>
#include <sys/stat.h>

struct find_subscribed_context {
	mailbox_list_callback_t *callback;
	void *context;
};

struct list_context {
	struct mail_storage *storage;
	struct imap_match_glob *glob;
	mailbox_list_callback_t *callback;
	void *context;

	const char *rootdir;
};

static int mbox_find_path(struct list_context *ctx, const char *relative_dir)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	const char *dir, *listpath;
	char fulldir[PATH_MAX], path[PATH_MAX], fullpath[PATH_MAX];
	int failed, match;
	size_t len;

	t_push();

	if (relative_dir == NULL)
		dir = ctx->rootdir;
	else if (*ctx->rootdir == '\0' && *relative_dir != '\0')
		dir = relative_dir;
	else {
		if (str_path(fulldir, sizeof(fulldir),
			     ctx->rootdir, relative_dir) < 0) {
			mail_storage_set_critical(ctx->storage,
						  "Path too long: %s",
						  relative_dir);
			return FALSE;
		}

		dir = fulldir;
	}

	dir = home_expand(dir);
	dirp = opendir(dir);
	if (dirp == NULL) {
		t_pop();

		if (relative_dir != NULL &&
		    (errno == ENOENT || errno == ENOTDIR)) {
			/* probably just race condition with other client
			   deleting the mailbox. */
			return TRUE;
		}

		if (errno == EACCES) {
			if (relative_dir != NULL) {
				/* subfolder, ignore */
				return TRUE;
			}
			mail_storage_set_error(ctx->storage, "Access denied");
			return FALSE;
		}

		mail_storage_set_critical(ctx->storage,
					  "opendir(%s) failed: %m", dir);
		return FALSE;
	}

	failed = FALSE;
	while ((d = readdir(dirp)) != NULL) {
		const char *fname = d->d_name;

		/* skip all hidden files */
		if (fname[0] == '.')
			continue;

		/* skip all .lock files */
		len = strlen(fname);
		if (len > 5 && strcmp(fname+len-5, ".lock") == 0)
			continue;

		/* check the mask */
		if (relative_dir == NULL)
			listpath = fname;
		else {
			if (str_path(path, sizeof(path),
				     relative_dir, fname) < 0) {
				mail_storage_set_critical(ctx->storage,
					"Path too long: %s/%s",
					relative_dir, fname);
				failed = TRUE;
				break;
			}
			listpath = path;
		}

		if ((match = imap_match(ctx->glob, listpath)) < 0)
			continue;

		/* see if it's a directory */
		if (str_path(fullpath, sizeof(fullpath), dir, fname) < 0) {
			mail_storage_set_critical(ctx->storage,
						  "Path too long: %s/%s",
						  dir, fname);
			failed = TRUE;
			break;
		}

		if (stat(fullpath, &st) < 0) {
			if (errno == ENOENT)
				continue; /* just deleted, ignore */

			mail_storage_set_critical(ctx->storage,
						  "stat(%s) failed: %m",
						  fullpath);
			failed = TRUE;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			/* subdirectory, scan it too */
			t_push();
			ctx->callback(ctx->storage, listpath, MAILBOX_NOSELECT,
				      ctx->context);
			t_pop();

			if (!mbox_find_path(ctx, listpath)) {
				failed = TRUE;
				break;
			}
		} else if (match > 0 &&
			   strcmp(fullpath, ctx->storage->inbox_file) != 0 &&
			   strcasecmp(listpath, "INBOX") != 0) {
			/* don't match any INBOX here, it's added later.
			   we might also have ~/mail/inbox, ~/mail/Inbox etc.
			   Just ignore them for now. */
			t_push();
			ctx->callback(ctx->storage, listpath,
				      MAILBOX_NOINFERIORS, ctx->context);
			t_pop();
		}
	}

	t_pop();

	(void)closedir(dirp);
	return !failed;
}

static const char *mask_get_dir(const char *mask)
{
	const char *p, *last_dir;

	last_dir = NULL;
	for (p = mask; *p != '\0' && *p != '%' && *p != '*'; p++) {
		if (*p == '/')
			last_dir = p;
	}

	return last_dir == NULL ? NULL : t_strdup_until(mask, last_dir);
}

int mbox_find_mailboxes(struct mail_storage *storage, const char *mask,
			mailbox_list_callback_t callback, void *context)
{
        struct list_context ctx;
	struct imap_match_glob *glob;
	const char *relative_dir;

	/* check that we're not trying to do any "../../" lists */
	if (!mbox_is_valid_mask(mask)) {
		mail_storage_set_error(storage, "Invalid mask");
		return FALSE;
	}

	mail_storage_clear_error(storage);

	/* if we're matching only subdirectories, don't bother scanning the
	   parent directories */
	relative_dir = mask_get_dir(mask);

	glob = imap_match_init(mask, TRUE, '/');
	if (relative_dir == NULL && imap_match(glob, "INBOX") > 0) {
		/* INBOX exists always, even if the file doesn't. */
		callback(storage, "INBOX", MAILBOX_NOINFERIORS, context);
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.storage = storage;
	ctx.glob = glob;
	ctx.callback = callback;
	ctx.context = context;

	if (!full_filesystem_access || relative_dir == NULL ||
	    (*relative_dir != '/' && *relative_dir != '~' &&
	     *relative_dir != '\0'))
		ctx.rootdir = storage->dir;
	else
		ctx.rootdir = "";

	if (relative_dir != NULL) {
		const char *matchdir = t_strconcat(relative_dir, "/", NULL);

		if (imap_match(ctx.glob, matchdir) > 0) {
			t_push();
			ctx.callback(ctx.storage, matchdir, MAILBOX_NOSELECT,
				     ctx.context);
			t_pop();
		}
	}

	if (!mbox_find_path(&ctx, relative_dir))
		return FALSE;

	return TRUE;
}

static int mbox_subs_cb(struct mail_storage *storage, const char *name,
			void *context)
{
	struct find_subscribed_context *ctx = context;
	enum mailbox_flags flags;
	struct stat st;
	char path[PATH_MAX];

	/* see if the mailbox exists, don't bother with the marked flags */
	if (strcasecmp(name, "INBOX") == 0) {
		/* inbox always exists */
		flags = 0;
	} else {
		flags = str_path(path, sizeof(path), storage->dir, name) == 0 &&
			stat(path, &st) == 0 && !S_ISDIR(st.st_mode) ?
			0 : MAILBOX_NOSELECT;
	}

	ctx->callback(storage, name, flags, ctx->context);
	return TRUE;
}

int mbox_find_subscribed(struct mail_storage *storage, const char *mask,
			 mailbox_list_callback_t callback, void *context)
{
	struct find_subscribed_context ctx;

	ctx.callback = callback;
	ctx.context = context;

	if (subsfile_foreach(storage, mask, mbox_subs_cb, &ctx) <= 0)
		return FALSE;

	return TRUE;
}
