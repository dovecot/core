/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-fs.h"

#include <sys/stat.h>

/* Assume that if atime < mtime, there are new mails. If it's good enough for
   UW-IMAP, it's good enough for us. */
#define STAT_GET_MARKED_FILE(st) \
	((st).st_size == 0 ? MAILBOX_UNMARKED : \
	 (st).st_atime < (st).st_mtime ? MAILBOX_MARKED : MAILBOX_UNMARKED)

static int
list_is_maildir_mailbox(struct mailbox_list *list, const char *dir,
			const char *fname, enum mailbox_list_file_type type,
			enum mailbox_info_flags *flags_r)
{
	const char *path, *maildir_path;
	struct stat st, st2;
	bool mailbox_files;

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_FILE:
	case MAILBOX_LIST_FILE_TYPE_OTHER:
		/* non-directories aren't valid */
		*flags_r |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		return 0;

	case MAILBOX_LIST_FILE_TYPE_DIR:
	case MAILBOX_LIST_FILE_TYPE_UNKNOWN:
	case MAILBOX_LIST_FILE_TYPE_SYMLINK:
		break;
	}

	path = t_strdup_printf("%s/%s", dir, fname);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		} else {
			/* non-selectable. probably either access denied, or
			   symlink destination not found. don't bother logging
			   errors. */
			*flags_r |= MAILBOX_NOSELECT;
			return 1;
		}
	}
	if (!S_ISDIR(st.st_mode)) {
		if (strncmp(fname, ".nfs", 4) == 0) {
			/* temporary NFS file */
			*flags_r |= MAILBOX_NONEXISTENT;
		} else {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
		}
		return 0;
	}

	/* ok, we've got a directory. see what we can do about it. */

	/* 1st link is "."
	   2nd link is ".."
	   3rd link is either child mailbox or mailbox dir
	   rest of the links are child mailboxes

	   if mailboxes are files, then 3+ links are all child mailboxes.
	*/
	mailbox_files = (list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0;
	if (st.st_nlink == 2 && !mailbox_files) {
		*flags_r |= MAILBOX_NOSELECT;
		return 1;
	}

	/* we have at least one directory. see if this mailbox is selectable */
	maildir_path = t_strconcat(path, "/", list->set.maildir_name, NULL);
	if (stat(maildir_path, &st2) < 0)
		*flags_r |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
	else if (!S_ISDIR(st2.st_mode)) {
		if (mailbox_files) {
			*flags_r |= st.st_nlink == 2 ?
				MAILBOX_NOCHILDREN : MAILBOX_CHILDREN;
		} else {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
		}
	} else {
		/* now we know what link count 3 means. */
		if (st.st_nlink == 3)
			*flags_r |= MAILBOX_NOCHILDREN;
		else
			*flags_r |= MAILBOX_CHILDREN;
	}
	*flags_r |= MAILBOX_SELECT;
	return 1;
}

static bool
is_inbox_file(struct mailbox_list *list, const char *path, const char *fname)
{
	const char *inbox_path;

	if (strcasecmp(fname, "INBOX") != 0)
		return FALSE;

	inbox_path = mailbox_list_get_path(list, "INBOX",
					   MAILBOX_LIST_PATH_TYPE_MAILBOX);
	return strcmp(inbox_path, path) == 0;
}

int fs_list_get_mailbox_flags(struct mailbox_list *list,
			      const char *dir, const char *fname,
			      enum mailbox_list_file_type type,
			      struct stat *st_r,
			      enum mailbox_info_flags *flags_r)
{
	struct stat st;
	const char *path;

	memset(st_r, 0, sizeof(*st_r));
	*flags_r = 0;

	if (*list->set.maildir_name != '\0') {
		/* maildir_name is set: we the code is common for all
		   storage types */
		return list_is_maildir_mailbox(list, dir, fname, type, flags_r);
	}
	if (list->v.is_internal_name != NULL &&
	    list->v.is_internal_name(list, fname)) {
		/* skip internal dirs */
		*flags_r |= MAILBOX_NOSELECT;
		return 0;
	}

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_DIR:
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
			return 1;
		}
		break;
	case MAILBOX_LIST_FILE_TYPE_FILE:
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			return 0;
		}
		break;
	default:
		break;
	}

	/* we've done all filtering we can before stat()ing */
	path = t_strconcat(dir, "/", fname, NULL);
	if (stat(path, &st) < 0) {
		if (ENOTFOUND(errno)) {
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		} else if (ENOACCESS(errno)) {
			*flags_r |= MAILBOX_NOSELECT;
			return 1;
		} else {
			/* non-selectable. probably either access denied, or
			   symlink destination not found. don't bother logging
			   errors. */
			mailbox_list_set_critical(list, "stat(%s) failed: %m",
						  path);
			return -1;
		}
	}
	*st_r = st;

	if (!S_ISDIR(st.st_mode)) {
		if (strncmp(fname, ".nfs", 4) == 0) {
			/* temporary NFS file */
			*flags_r |= MAILBOX_NONEXISTENT;
			return 0;
		}

		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_NOINFERIORS;
			return 0;
		}
		/* looks like a valid mailbox file */
		if (is_inbox_file(list, path, fname) &&
		    strcmp(fname, "INBOX") != 0) {
			/* it's possible for INBOX to have child
			   mailboxes as long as the inbox file itself
			   isn't in <mail root>/INBOX */
		} else {
			*flags_r |= MAILBOX_NOINFERIORS;
		}
	} else {
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
			*flags_r |= MAILBOX_NOSELECT | MAILBOX_CHILDREN;
			return 1;
		}
	}

	if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		*flags_r |= STAT_GET_MARKED_FILE(st);
	} else if (list->v.is_internal_name == NULL) {
		/* link count < 2 can happen with filesystems that don't
		   support link counts. we'll just ignore them for now.. */
		if (st.st_nlink == 2)
			*flags_r |= MAILBOX_NOCHILDREN;
		else if (st.st_nlink > 2)
			*flags_r |= MAILBOX_CHILDREN;
	}
	return 1;
}
