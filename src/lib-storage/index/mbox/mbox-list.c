/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "unlink-directory.h"
#include "imap-match.h"
#include "subscription-file/subscription-file.h"
#include "mbox-index.h"
#include "mbox-storage.h"

#include <dirent.h>
#include <sys/stat.h>

typedef struct {
	MailboxFunc func;
	void *context;
} FindSubscribedContext;

static int mbox_find_path(MailStorage *storage, ImapMatchGlob *glob,
			  MailboxFunc func, void *context,
			  const char *relative_dir, int *found_inbox)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	const char *dir, *listpath;
	char fulldir[1024], path[1024], fullpath[1024];
	int failed, match;
	size_t len;

	t_push();

	if (relative_dir == NULL)
		dir = storage->dir;
	else {
		i_snprintf(fulldir, sizeof(fulldir), "%s/%s",
			   storage->dir, relative_dir);
		dir = fulldir;
	}

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno != ENOENT && errno != ENOTDIR) {
			mail_storage_set_critical(storage,
				"opendir(%s) failed: %m", dir);
		}
		t_pop();
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
			i_snprintf(path, sizeof(path), "%s/%s",
				   relative_dir, fname);
			listpath = path;
		}

		if ((match = imap_match(glob, listpath)) < 0)
			continue;

		/* see if it's a directory */
		i_snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, fname);
		if (stat(fullpath, &st) != 0) {
			if (errno == ENOENT)
				continue; /* just deleted, ignore */

			mail_storage_set_critical(storage, "stat(%s) failed: "
						  "%m", fullpath);
			failed = TRUE;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			/* subdirectory, scan it too */
			func(storage, listpath, MAILBOX_NOSELECT, context);

			if (!mbox_find_path(storage, glob, func,
					    context, listpath, NULL)) {
				failed = TRUE;
				break;
			}
		} else if (match > 0) {
			if (found_inbox != NULL &&
			    strcasecmp(listpath, "inbox") == 0)
				*found_inbox = TRUE;

			func(storage, listpath, MAILBOX_NOINFERIORS, context);
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

	return last_dir != NULL ? t_strdup_until(mask, last_dir) : NULL;
}

int mbox_find_mailboxes(MailStorage *storage, const char *mask,
			MailboxFunc func, void *context)
{
	ImapMatchGlob *glob;
	const char *relative_dir;
	int found_inbox;

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

	found_inbox = FALSE;
	if (!mbox_find_path(storage, glob, func, context,
			    relative_dir, &found_inbox))
		return FALSE;

	if (!found_inbox && relative_dir == NULL &&
	    imap_match(glob, "INBOX") > 0) {
		/* INBOX always exists, even if the file doesn't. */
		func(storage, "INBOX", MAILBOX_UNMARKED | MAILBOX_NOINFERIORS,
		     context);
	}

	return TRUE;
}

static int mbox_subs_func(MailStorage *storage, const char *name,
			  void *context)
{
	FindSubscribedContext *ctx = context;
	MailboxFlags flags;
	struct stat st;
	char path[1024];

	/* see if the mailbox exists, don't bother with the marked flags */
	if (strcasecmp(name, "INBOX") == 0) {
		/* inbox always exists */
		flags = 0;
	} else {
		i_snprintf(path, sizeof(path), "%s/%s", storage->dir, name);
		flags = stat(path, &st) == 0 && !S_ISDIR(st.st_mode) ?
			0 : MAILBOX_NOSELECT;
	}

	ctx->func(storage, name, flags, ctx->context);
	return TRUE;
}

int mbox_find_subscribed(MailStorage *storage, const char *mask,
			 MailboxFunc func, void *context)
{
	FindSubscribedContext ctx;

	ctx.func = func;
	ctx.context = context;

	if (subsfile_foreach(storage, mask, mbox_subs_func, &ctx) <= 0)
		return FALSE;

	return TRUE;
}
