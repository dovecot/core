/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
		if (str_begins(fname, ".nfs")) {
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

	if (mailbox_list_get_path(list, "INBOX",
				  MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &inbox_path) <= 0)
		i_unreached();
	return strcmp(inbox_path, path) == 0;
}

int fs_list_get_mailbox_flags(struct mailbox_list *list,
			      const char *dir, const char *fname,
			      enum mailbox_list_file_type type,
			      enum mailbox_info_flags *flags_r)
{
	struct stat st;
	const char *path;

	*flags_r = 0;

	if (*list->set.maildir_name != '\0' && !list->set.iter_from_index_dir) {
		/* maildir_name is set: This is the simple case that works for
		   all mail storage formats, because the only thing that
		   matters for existence or child checks is whether the
		   maildir_name exists or not. For example with Maildir this
		   doesn't care whether the "cur" directory exists; as long
		   as the parent maildir_name exists, the Maildir is
		   selectable. */
		return list_is_maildir_mailbox(list, dir, fname, type, flags_r);
	}
	/* maildir_name is not set: Now we (may) need to use storage-specific
	   code to determine whether the mailbox is selectable or if it has
	   children.

	   We're here also when iterating from index directory, because even
	   though maildir_name is set, it's not used for index directory.
	*/

	if (!list->set.iter_from_index_dir &&
	    list->v.is_internal_name != NULL &&
	    list->v.is_internal_name(list, fname)) {
		/* skip internal dirs. For example Maildir's cur/new/tmp */
		*flags_r |= MAILBOX_NOSELECT;
		return 0;
	}

	switch (type) {
	case MAILBOX_LIST_FILE_TYPE_DIR:
		/* We know that we're looking at a directory. If the storage
		   uses files, it has to be a \NoSelect directory. */
		if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
			*flags_r |= MAILBOX_NOSELECT;
			return 1;
		}
		break;
	case MAILBOX_LIST_FILE_TYPE_FILE:
		/* We know that we're looking at a file. If the storage
		   doesn't use files, it's not a mailbox and we want to skip
		   it. */
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

	if (!S_ISDIR(st.st_mode)) {
		if (str_begins(fname, ".nfs")) {
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
		/* Return mailbox files as always existing. The current
		   mailbox_exists() code would do the same stat() anyway
		   without further checks, so might as well avoid the second
		   stat(). */
		*flags_r |= MAILBOX_SELECT;
		*flags_r |= STAT_GET_MARKED_FILE(st);
		return 1;
	}

	/* This is a directory */
	if ((list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0) {
		/* We should get here only if type is
		   MAILBOX_LIST_FILE_TYPE_UNKNOWN because the filesystem didn't
		   return the type. Normally this should have already been
		   handled by the MAILBOX_LIST_FILE_TYPE_DIR check above. */
		*flags_r |= MAILBOX_NOSELECT;
		return 1;
	}

	if (list->v.is_internal_name == NULL || list->set.iter_from_index_dir) {
		/* This mailbox format doesn't use any special directories
		   (e.g. Maildir's cur/new/tmp). In that case we can look at
		   the directory's link count to determine whether there are
		   children or not. The directory's link count equals the
		   number of subdirectories it has. The first two links are
		   for "." and "..".

		   link count < 2 can happen with filesystems that don't
		   support link counts. we'll just ignore them for now.. */
		if (st.st_nlink == 2)
			*flags_r |= MAILBOX_NOCHILDREN;
		else if (st.st_nlink > 2)
			*flags_r |= MAILBOX_CHILDREN;
	}
	return 1;
}
