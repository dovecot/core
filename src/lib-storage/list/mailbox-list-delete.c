/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

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

	root_dir = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_DIR);
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

	random_fill(randbuf, sizeof(randbuf));
	return t_strdup_printf("%s.%s.%s", my_hostname, my_pid,
			       binary_to_hex(randbuf, sizeof(randbuf)));

}

int mailbox_list_delete_maildir_via_trash(struct mailbox_list *list,
					  const char *name,
					  const char *trash_dir)
{
	const char *src, *trash_dest, *error;
	unsigned int count;

	if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &src) <= 0)
		i_unreached();
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
				T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
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
		} else if (mailbox_list_delete_trash(trash_dest, &error) < 0 &&
			   (errno != ENOTEMPTY || count >= 5)) {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %s", trash_dest, error);
			return -1;
		}
	}

	if (mailbox_list_delete_trash(trash_dir, &error) < 0 &&
	    errno != ENOTEMPTY && errno != EBUSY) {
		mailbox_list_set_critical(list,
			"unlink_directory(%s) failed: %s", trash_dir, error);

		/* it's already renamed to trash dir, which means it's
		   deleted as far as the client is concerned. Report
		   success. */
	}
	return 1;
}

int mailbox_list_delete_mailbox_file(struct mailbox_list *list,
				     const char *name, const char *path)
{
	/* we can simply unlink() the file */
	if (unlink(path) == 0)
		return 0;
	else if (ENOTFOUND(errno)) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				       T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
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
	size_t dir_len;
	const char *error;
	bool mailbox_dir, unlinked_something = FALSE;
	int ret = 0;

	if (mailbox_list_check_root_delete(list, name, path) < 0)
		return -1;

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
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
			if (mailbox_list_delete_trash(str_c(full_path), &error) < 0) {
				mailbox_list_set_critical(list,
					"unlink_directory(%s) failed: %s",
					str_c(full_path), error);
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
		else if (errno != ENOENT && !UNLINK_EISDIR(errno)) {
			mailbox_list_set_critical(list,
				"unlink(%s) failed: %m", str_c(full_path));
			ret = -1;
		} else {
			/* child directories still exist */
			rmdir_path = FALSE;
		}
	}
	if (errno != 0) {
		mailbox_list_set_critical(list, "readdir(%s) failed: %m", path);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		mailbox_list_set_critical(list, "closedir(%s) failed: %m",
					  path);
		ret = -1;
	}
	if (ret < 0)
		return -1;

	if (rmdir_path) {
		unsigned int try_count = 0;
		int ret = rmdir(path);
		while (ret < 0 && errno == ENOTEMPTY && try_count++ < 10) {
			/* We didn't see any child directories, so this is
			   either a race condition or .nfs* files were left
			   lying around. In case it's .nfs* files, retry after
			   waiting a bit. Hopefully all processes keeping those
			   files open will have closed them by then. */
			usleep(100000);
			ret = rmdir(path);
		}
		if (rmdir(path) == 0)
			unlinked_something = TRUE;
		else if (errno == ENOENT) {
			/* race condition with another process, which finished
			   deleting it first. */
			mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
				T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
		} else if (errno != ENOTEMPTY && errno != EEXIST) {
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

static bool mailbox_list_path_is_index(struct mailbox_list *list,
				       enum mailbox_list_path_type type)
{
	const char *index_root, *type_root;

	if (type == MAILBOX_LIST_PATH_TYPE_INDEX)
		return TRUE;

	/* e.g. CONTROL dir could point to the same INDEX dir. */
	type_root = mailbox_list_get_root_forced(list, type);
	index_root = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_INDEX);
	return strcmp(type_root, index_root) == 0;
}

void mailbox_list_delete_until_root(struct mailbox_list *list, const char *path,
				    enum mailbox_list_path_type type)
{
	const char *root_dir, *p;
	size_t len;

	if (list->set.iter_from_index_dir && !list->set.no_noselect &&
	    mailbox_list_path_is_index(list, type)) {
		/* Don't auto-rmdir parent index directories with ITERINDEX.
		   Otherwise it'll get us into inconsistent state with a
		   \NoSelect mailbox in the mail directory but not in index
		   directory. */
		return;
	}

	root_dir = mailbox_list_get_root_forced(list, type);
	if (!str_begins(path, root_dir)) {
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

void mailbox_list_delete_mailbox_until_root(struct mailbox_list *list,
					    const char *storage_name)
{
	enum mailbox_list_path_type types[] = {
		MAILBOX_LIST_PATH_TYPE_DIR,
		MAILBOX_LIST_PATH_TYPE_ALT_DIR,
		MAILBOX_LIST_PATH_TYPE_CONTROL,
		MAILBOX_LIST_PATH_TYPE_INDEX,
		MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE,
		MAILBOX_LIST_PATH_TYPE_INDEX_CACHE,
	};
	const char *path;

	for (unsigned int i = 0; i < N_ELEMENTS(types); i++) {
		if (mailbox_list_get_path(list, storage_name, types[i], &path) > 0)
			mailbox_list_delete_until_root(list, path, types[i]);
	}
}

static int mailbox_list_try_delete(struct mailbox_list *list, const char *name,
				   enum mailbox_list_path_type type)
{
	const char *mailbox_path, *index_path, *path, *error;
	int ret;

	if (mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				  &mailbox_path) <= 0 ||
	    mailbox_list_get_path(list, name, type, &path) <= 0 ||
	    strcmp(path, mailbox_path) == 0)
		return 0;

	if (type == MAILBOX_LIST_PATH_TYPE_CONTROL &&
	    mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_INDEX,
				  &index_path) > 0 &&
	    strcmp(index_path, path) == 0) {
		/* CONTROL dir is the same as INDEX dir, which we already
		   deleted. We don't want to continue especially with
		   iter_from_index_dir=yes, because it could be deleting the
		   index directory. */
		return 0;
	}

	/* Note that only ALT currently uses maildir_name in paths.
	   INDEX and CONTROL don't. */
	if (type != MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX ||
	    *list->set.maildir_name == '\0') {
		/* this directory may contain also child mailboxes' data.
		   we don't want to delete that. */
		bool rmdir_path = *list->set.maildir_name != '\0';
		if (mailbox_list_delete_mailbox_nonrecursive(list, name, path,
							     rmdir_path) == 0)
			ret = 1;
		else {
			enum mail_error error =
				mailbox_list_get_last_mail_error(list);
			if (error != MAIL_ERROR_NOTFOUND &&
			    error != MAIL_ERROR_NOTPOSSIBLE)
				return -1;
			ret = 0;
		}
	} else {
		if (mailbox_list_delete_trash(path, &error) == 0)
			ret = 1;
		else if (errno == ENOTEMPTY)
			ret = 0;
		else {
			mailbox_list_set_critical(list,
				"unlink_directory(%s) failed: %s", path, error);
			return -1;
		}
	}

	/* Avoid leaving empty parent directories lying around.
	   These parent directories' existence or removal doesn't
	   affect our return value. */
	mailbox_list_delete_until_root(list, path, type);
	return ret;
}

int mailbox_list_delete_finish(struct mailbox_list *list, const char *name)
{
	int ret, ret2;

	ret = mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_INDEX);
	ret2 = mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_INDEX_CACHE);
	if (ret == 0 || ret2 < 0)
		ret = ret2;
	ret2 = mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_CONTROL);
	if (ret == 0 || ret2 < 0)
		ret = ret2;
	ret2 = mailbox_list_try_delete(list, name, MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX);
	if (ret == 0 || ret2 < 0)
		ret = ret2;
	return ret;
}

int mailbox_list_delete_finish_ret(struct mailbox_list *list,
				   const char *name, bool root_delete_success)
{
	int ret2;

	if (!root_delete_success &&
	    mailbox_list_get_last_mail_error(list) != MAIL_ERROR_NOTFOUND) {
		/* unexpected error - preserve it */
		return -1;
	} else if ((ret2 = mailbox_list_delete_finish(list, name)) < 0) {
		/* unexpected error */
		return -1;
	} else if (ret2 > 0) {
		/* successfully deleted */
		return 0;
	} else if (root_delete_success) {
		/* nothing deleted by us, but root was successfully deleted */
		return 0;
	} else {
		/* nothing deleted by us and the root didn't exist either.
		   make sure the list has the correct error set, since it
		   could have been changed. */
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
		return -1;
	}
}

int mailbox_list_delete_trash(const char *path, const char **error_r)
{
	if (unlink_directory(path, UNLINK_DIRECTORY_FLAG_RMDIR, error_r) < 0) {
		if (errno == ELOOP) {
			/* it's a symlink? try just deleting it */
			if (unlink(path) == 0)
				return 0;
			errno = ELOOP;
			return -1;
		}
		return -1;
	}
	return 0;
}

int mailbox_list_delete_symlink_default(struct mailbox_list *list,
					const char *name)
{
	const char *path;
	int ret;

	ret = mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_DIR,
				    &path);
	if (ret < 0)
		return -1;
	i_assert(ret > 0);

	if (unlink(path) == 0)
		return 0;

	if (errno == ENOENT) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAILBOX_LIST_ERR_NOT_FOUND(list, name));
	} else if (UNLINK_EISDIR(errno)) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox isn't a symlink");
	} else {
		mailbox_list_set_critical(list, "unlink(%s) failed: %m", path);
	}
	return -1;
}
