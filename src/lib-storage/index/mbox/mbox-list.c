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
	void *user_data;
} FindSubscribedData;

static int mbox_find_path(MailStorage *storage, const ImapMatchGlob *glob,
			  MailboxFunc func, void *user_data,
			  const char *relative_dir, int *found_inbox)
{
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	const char *dir;
	char fulldir[1024], path[1024];
	int failed, len;

	if (relative_dir == NULL)
		dir = storage->dir;
	else {
		i_snprintf(fulldir, sizeof(fulldir), "%s/%s",
			   storage->dir, relative_dir);
		dir = fulldir;
	}

	dirp = opendir(dir);
	if (dirp == NULL) {
		mail_storage_set_critical(storage, "opendir(%s) failed: %m",
					  dir);
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

		/* make sure the mask matches */
		if (relative_dir == NULL) {
			if (imap_match(glob, fname, 0, NULL) < 0)
				continue;
		} else {
			i_snprintf(path, sizeof(path),
				   "%s/%s", relative_dir, fname);
			if (imap_match(glob, path, 0, NULL) < 0)
				continue;
		}

		/* see if it's a directory */
		i_snprintf(path, sizeof(path), "%s/%s", dir, fname);
		if (stat(path, &st) != 0) {
			if (errno == ENOENT)
				continue; /* just deleted, ignore */

			mail_storage_set_critical(storage, "stat(%s) failed: "
						  "%m", path);
			failed = TRUE;
			break;
		}

		if (relative_dir == NULL) {
			strncpy(path, fname, sizeof(path)-1);
			path[sizeof(path)-1] = '\0';
		} else {
			i_snprintf(path, sizeof(path), "%s/%s",
				   relative_dir, fname);
		}

		if (S_ISDIR(st.st_mode)) {
			/* subdirectory, scan it too */
			if (!mbox_find_path(storage, glob, func,
					    user_data, path, NULL)) {
				failed = TRUE;
				break;
			}
		} else {
			if (found_inbox != NULL &&
			    strcasecmp(path, "inbox") == 0)
				*found_inbox = TRUE;

			func(storage, path, MAILBOX_NOINFERIORS, user_data);
		}
	}

	(void)closedir(dirp);
	return !failed;
}

int mbox_find_mailboxes(MailStorage *storage, const char *mask,
			MailboxFunc func, void *user_data)
{
        const ImapMatchGlob *glob;
	int found_inbox;

	mail_storage_clear_error(storage);

	glob = imap_match_init(mask, TRUE, '/');

	found_inbox = FALSE;
	if (!mbox_find_path(storage, glob, func, user_data,
			    NULL, &found_inbox))
		return FALSE;

	if (!found_inbox && imap_match(glob, "INBOX", 0, NULL) < 0) {
		/* INBOX always exists */
		func(storage, "INBOX", MAILBOX_UNMARKED | MAILBOX_NOINFERIORS,
		     user_data);
	}

	return TRUE;
}

static int mbox_subs_func(MailStorage *storage, const char *name,
			  void *user_data)
{
	FindSubscribedData *data = user_data;
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

	data->func(storage, name, flags, data->user_data);
	return TRUE;
}

int mbox_find_subscribed(MailStorage *storage, const char *mask,
			 MailboxFunc func, void *user_data)
{
	FindSubscribedData data;

	data.func = func;
	data.user_data = user_data;

	if (subsfile_foreach(storage, mask, mbox_subs_func, &data) <= 0)
		return FALSE;

	return TRUE;
}
