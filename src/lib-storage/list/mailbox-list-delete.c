/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "randgen.h"
#include "unlink-directory.h"
#include "mailbox-list-private.h"
#include "mailbox-list-delete.h"

#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

static int
mailbox_list_check_root_delete(struct mailbox_list *list, const char *name,
			       const char *path)
{
	const char *root_dir;

	root_dir = mailbox_list_get_path(list, NULL,
					 MAILBOX_LIST_PATH_TYPE_DIR);
	if (strcmp(root_dir, path) != 0)
		return 0;

	if (strcmp(name, "INBOX") == 0 &&
	    (list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "INBOX can't be deleted.");
		return -1;
	}
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
			       "Mail storage root can't be deleted.");
	return -1;
}

static const char *unique_fname(void)
{
	unsigned char randbuf[8];

	random_fill_weak(randbuf, sizeof(randbuf));
	return t_strdup_printf("%s.%s.%s", my_hostname, my_pid,
			       binary_to_hex(randbuf, sizeof(randbuf)));

}

int mailbox_list_delete_maildir_via_trash(struct mailbox_list *list,
					  const char *name,
					  const char *trash_dir)
{
	const char *src, *trash_dest;
	unsigned int count;

	src = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	if (mailbox_list_check_root_delete(list, name, src) < 0)
		return -1;

	/* rename the mailbox dir to trash dir, which atomically
	   marks it as being deleted. */
	count = 0; trash_dest = trash_dir;
	for (; rename(src, trash_dest) < 0; count++) {
		if (ENOTFOUND(errno)) {
			if (trash_dest != trash_dir && count < 5) {
				/* either the source was just deleted or
				   the trash dir was deleted. */
				trash_dest = trash_dir;
				continue;
			}
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
			return -1;
		}
		if (errno == EXDEV) {
			/* can't do this the fast way */
			return 0;
		}
		if (!EDESTDIREXISTS(errno)) {
			if (mailbox_list_set_error_from_errno(list))
				return -1;
			mailbox_list_set_critical(list,
				"rename(%s, %s) failed: %m", src, trash_dest);
			return -1;
		}

		/* trash dir already exists. the reasons for this are:

		   a) another process is in the middle of deleting it
		   b) previous process crashed and didn't delete it
		   c) NFS: mailbox was recently deleted, but some connection
		      still has that mailbox open. the directory contains .nfs*
		      files that can't be deleted until the mailbox is closed.

		   Because of c) we'll first try to rename the mailbox under
		   the trash directory and only later try to delete the entire
		   trash directory. */
		if (trash_dir == trash_dest) {
			trash_dest = t_strconcat(trash_dir, "/",
						 unique_fname(), NULL);
		} else if (mailbox_list_delete_trash(trash_dest) < 0 &&
			   (errno != ENOTEMPTY || count >= 5)) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", trash_dest);
			return -1;
		}
	}

	if (mailbox_list_delete_trash(trash_dir) < 0 &&
	    errno != ENOTEMPTY && errno != EBUSY) {
		mailbox_list_set_critical(list,
			"unlink_directory(%s) failed: %m", trash_dir);

		/* it's already renamed to trash dir, which means it's
		   deleted as far as the client is concerned. Report
		   success. */
	}
	return 1;
}

int mailbox_list_delete_mailbox_file(struct mailbox_list *list,
				     const char *name)
{
	const char *path;

	path = mailbox_list_get_path(list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);

	/* we can simply unlink() the file */
	if (unlink(path) == 0)
		return 0;
	else if (ENOTFOUND(errno)) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				       T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	} else {
		if (!mailbox_list_set_error_from_errno(list)) {
			mailbox_list_set_critical(list,
				"unlink(%s) failed: %m", path);
		}
		return -1;
	}
}

int mailbox_list_delete_mailbox_nonrecursive(struct mailbox_list *list,
					     const char *name, const char *path,
					     bool rmdir_path)
{
	DIR *dir;
	struct dirent *d;
	string_t *full_path;
	unsigned int dir_len;
	bool mailbox_dir, unlinked_something = FALSE;

	if (mailbox_list_check_root_delete(list, name, path) < 0)
		return -1;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		} else {
			if (!mailbox_list_set_error_from_errno(list)) {
				mailbox_list_set_critical(list,
					"opendir(%s) failed: %m", path);
			}
		}
		return -1;
	}

	full_path = t_str_new(256);
	str_append(full_path, path);
	str_append_c(full_path, '/');
	dir_len = str_len(full_path);

	for (errno = 0; (d = readdir(dir)) != NULL; errno = 0) {
		if (d->d_name[0] == '.') {
			/* skip . and .. */
			if (d->d_name[1] == '\0')
				continue;
			if (d->d_name[1] == '.' && d->d_name[2] == '\0')
				continue;
		}

		mailbox_dir = list->v.is_internal_name != NULL &&
			list->v.is_internal_name(list, d->d_name);

		str_truncate(full_path, dir_len);
		str_append(full_path, d->d_name);

		if (mailbox_dir) {
			if (mailbox_list_delete_trash(str_c(full_path)) < 0) {
				mailbox_list_set_critical(list,
					"unlink_directory(%s) failed: %m",
					str_c(full_path));
			} else {
				unlinked_something = TRUE;
			}
			continue;
		}

		/* trying to unlink() a directory gives either EPERM or EISDIR
		   (non-POSIX). it doesn't really work anywhere in practise,
		   so don't bother stat()ing the file first */
		if (unlink(str_c(full_path)) == 0)
			unlinked_something = TRUE;
		else if (errno != ENOENT && errno != EISDIR && errno != EPERM) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m",
				str_c(full_path));
		}
	}
	if (errno != 0)
		mailbox_list_set_critical(list, "readdir(%s) failed: %m", path);
	if (closedir(dir) < 0) {
		mailbox_list_set_critical(list, "closedir(%s) failed: %m",
					  path);
	}

	if (rmdir_path) {
		if (rmdir(path) == 0)
			unlinked_something = TRUE;
		else if (errno != ENOENT &&
			 errno != ENOTEMPTY && errno != EEXIST) {
			mailbox_list_set_critical(list, "rmdir(%s) failed: %m",
						  path);
			return -1;
		}
	}

	if (!unlinked_something) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox has children, can't delete it");
		return -1;
	}
	return 0;
}

void mailbox_list_delete_until_root(struct mailbox_list *list, const char *path,
				    enum mailbox_list_path_type type)
{
	const char *root_dir, *p;
	unsigned int len;

	root_dir = mailbox_list_get_path(list, NULL, type);
	if (strncmp(path, root_dir, strlen(root_dir)) != 0) {
		/* mbox workaround: name=child/box, root_dir=mail/.imap/,
		   path=mail/child/.imap/box. we'll want to try to delete
		   the .imap/ part, but no further. */
		len = strlen(path);
		while (len > 0 && path[len-1] != '/')
			len--;
		if (len == 0)
			return;
		len--;
		while (len > 0 && path[len-1] != '/')
			len--;
		if (len == 0)
			return;

		root_dir = t_strndup(path, len-1);
	}
	while (strcmp(path, root_dir) != 0) {
		if (rmdir(path) < 0 && errno != ENOENT) {
			if (errno == ENOTEMPTY || errno == EEXIST)
				return;

			mailbox_list_set_critical(list, "rmdir(%s) failed: %m",
						  path);
			return;
		}
		p = strrchr(path, '/');
		if (p == NULL)
			break;

		path = t_strdup_until(path, p);
	}
}

static void mailbox_list_try_delete(struct mailbox_list *list, const char *name,
				    enum mailbox_list_path_type type)
{
	const char *mailbox_path, *path;

	mailbox_path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	path = mailbox_list_get_path(list, name, type);
	if (path == NULL || *path == '\0' || strcmp(path, mailbox_path) == 0)
		return;

	if (*list->set.maildir_name == '\0' &&
	    (list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
		/* this directory may contain also child mailboxes' data.
		   we don't want to delete that. */
		bool rmdir_path = *list->set.maildir_name != '\0';
		if (mailbox_list_delete_mailbox_nonrecursive(list, name, path,
							     rmdir_path) < 0)
			return;
	} else {
		if (mailbox_list_delete_trash(path) < 0 &&
		    errno != ENOENT && errno != ENOTEMPTY) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %m", path);
		}
	}

	/* avoid leaving empty directories lying around */
	mailbox_list_delete_until_root(list, path, type);
}

void mailbox_list_delete_finish(struct mailbox_list *list, const char *name)
{
	mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_INDEX);
	mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_CONTROL);
	mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX);
}

int mailbox_list_delete_trash(const char *path)
{
	if (unlink_directory(path, TRUE) < 0) {
		if (errno == ELOOP) {
			/* it's a symlink? try just deleting it */
			if (unlink(path) == 0)
				return 0;
			errno = ELOOP;
			return -1;
		}
	}
	return 0;
}
