/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "convert-storage.h"

#include <stdio.h>
#include <dirent.h>

#define CONVERT_LOCK_FILENAME ".dovecot.convert"

struct dotlock_settings dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 60*5,
	MEMBER(stale_timeout) 60*5
};

static const char *storage_error(struct mail_storage *storage)
{
	enum mail_error error;

	return mail_storage_get_last_error(storage, &error);
}

static int mailbox_copy_mails(struct mailbox *srcbox, struct mailbox *destbox,
			      struct dotlock *dotlock, const char **error_r)
{
	struct mail_search_context *ctx;
	struct mailbox_transaction_context *src_trans, *dest_trans;
	struct mail *mail;
	struct mail_search_args *search_args;
	int ret = 0;

	if (mailbox_sync(srcbox, MAILBOX_SYNC_FLAG_FULL_READ, 0, NULL) < 0) {
		*error_r = storage_error(srcbox->storage);
		return -1;
	}
	*error_r = NULL;

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	src_trans = mailbox_transaction_begin(srcbox, 0);
	dest_trans = mailbox_transaction_begin(destbox,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	ctx = mailbox_search_init(src_trans, search_args, NULL);
	mail_search_args_unref(&search_args);

	mail = mail_alloc(src_trans,
			  MAIL_FETCH_FLAGS | MAIL_FETCH_RECEIVED_DATE |
			  MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY |
			  MAIL_FETCH_FROM_ENVELOPE, NULL);
	while (mailbox_search_next(ctx, mail) > 0) {
		struct mail_keywords *keywords;
		const char *const *keywords_list;

		if ((mail->seq % 100) == 0) {
			/* touch the lock file so that if there are tons of
			   mails another process won't override our lock. */
			(void)file_dotlock_touch(dotlock);
		}

		keywords_list = mail_get_keywords(mail);
		keywords = str_array_length(keywords_list) == 0 ? NULL :
			mailbox_keywords_create_valid(destbox, keywords_list);

		ret = mailbox_copy(dest_trans, mail, mail_get_flags(mail),
				   keywords, NULL);
		mailbox_keywords_free(destbox, &keywords);
		if (ret < 0) {
			*error_r = storage_error(destbox->storage);
			break;
		}
	}

	mail_free(&mail);
	if (mailbox_search_deinit(&ctx) < 0) {
		ret = -1;
		*error_r = storage_error(srcbox->storage);
	}

	if (ret < 0)
		mailbox_transaction_rollback(&dest_trans);
	else {
		ret = mailbox_transaction_commit(&dest_trans);
		if (ret < 0)
			*error_r = storage_error(destbox->storage);
	}

	/* source transaction committing isn't all that important.
	   ignore if it fails. */
	if (ret < 0)
		mailbox_transaction_rollback(&src_trans);
	else
		(void)mailbox_transaction_commit(&src_trans);
	i_assert(ret == 0 || *error_r != NULL);
	return ret;
}

static const char *
mailbox_name_convert(struct mail_storage *dest_storage,
		     struct mail_storage *source_storage,
		     const struct convert_settings *set, const char *name)
{
	char *dest_name, *p, src_sep, dest_sep;

	src_sep = mail_storage_get_hierarchy_sep(source_storage);
	dest_sep = mail_storage_get_hierarchy_sep(dest_storage);

	if (src_sep == dest_sep)
		return name;

	dest_name = t_strdup_noconst(name);
	for (p = dest_name; *p != '\0'; p++) {
		if (*p == dest_sep)
			*p = set->alt_hierarchy_char;
		else if (*p == src_sep)
			*p = dest_sep;
	}
	return dest_name;
}

static int mailbox_convert_maildir_to_dbox(struct mail_storage *src_storage,
					   struct mail_storage *dest_storage,
					   const char *src_name,
					   const char *dest_name)
{
	static const char *maildir_files[] = {
		"dovecot-uidlist",
		"dovecot-keywords",
		"dovecot.index",
		"dovecot.index.log",
		"dovecot.index.cache"
	};
	string_t *src, *dest;
	DIR *dir;
	struct dirent *dp;
	const char *src_path, *dest_path, *new_path, *cur_path;
	unsigned int i, src_dir_len, dest_dir_len;
	bool t;
	int ret;

	/* create as non-selectable mailbox so the dbox-Mails directory
	   isn't created yet */
	if (mail_storage_mailbox_create(dest_storage, dest_name, TRUE) < 0) {
		i_error("Mailbox conversion: "
			"Couldn't create mailbox %s: %s",
			dest_name, storage_error(dest_storage));
		return -1;
	}

	src_path = mail_storage_get_mailbox_path(src_storage, src_name, &t);
	dest_path = mail_storage_get_mailbox_path(dest_storage, dest_name, &t);

	/* rename cur/ directory as the destination directory */
	cur_path = t_strconcat(src_path, "/cur", NULL);

	if (rename(cur_path, dest_path) < 0) {
		i_error("rename(%s, %s) failed: %m", cur_path, dest_path);
		return -1;
	}

	/* move metadata files */
	src = t_str_new(256);
	str_printfa(src, "%s/", src_path);
	src_dir_len = str_len(src);

	dest = t_str_new(256);
	str_printfa(dest, "%s/", dest_path);
	dest_dir_len = str_len(dest);

	for (i = 0; i < N_ELEMENTS(maildir_files); i++) {
		str_truncate(src, src_dir_len);
		str_truncate(dest, dest_dir_len);
		str_append(src, maildir_files[i]);
		str_append(dest, maildir_files[i]);

		if (rename(str_c(src), str_c(dest)) < 0 && errno != ENOENT) {
			i_error("rename(%s, %s) failed: %m",
				str_c(src), str_c(dest));
		}
	}

	/* move files in new/ */
	new_path = t_strconcat(src_path, "/new", NULL);
	str_truncate(src, src_dir_len);
	str_append(src, "new/");
	src_dir_len = str_len(src);

	dir = opendir(new_path);
	if (dir == NULL) {
		if (errno == ENOENT)
			return 0;

		i_error("opendir(%s) failed: %m", new_path);
		return -1;
	}
	ret = 0;
	errno = 0;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.' &&
		    (dp->d_name[1] == '\0' ||
		     (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;

		str_truncate(src, src_dir_len);
		str_truncate(dest, dest_dir_len);
		str_append(src, dp->d_name);
		str_append(dest, dp->d_name);

		if (strstr(dp->d_name, ":2,") == NULL)
			str_append(dest, ":2,");

		if (rename(str_c(src), str_c(dest)) < 0) {
			i_error("rename(%s, %s) failed: %m",
				str_c(src), str_c(dest));
			ret = -1;
			errno = 0;
		}
	}
	if (errno != 0) {
		i_error("readdir(%s) failed: %m", new_path);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		i_error("closedir(%s) failed: %m", new_path);
		ret = -1;
	}
	return ret;
}

static int mailbox_convert_list_item(struct mail_storage *source_storage,
				     struct mail_storage *dest_storage,
				     const struct mailbox_info *info,
				     struct dotlock *dotlock,
				     const struct convert_settings *set)
{
	const char *name, *dest_name, *error;
	struct mailbox *srcbox, *destbox;
	int ret = 0;

	if ((info->flags & MAILBOX_NONEXISTENT) != 0)
		return 0;

	name = strcasecmp(info->name, "INBOX") == 0 ? "INBOX" : info->name;
	dest_name = mailbox_name_convert(dest_storage, source_storage,
					 set, name);

	if ((info->flags & MAILBOX_NOSELECT) != 0) {
		/* \NoSelect mailbox, so it's probably a "directory" */
		if (*info->name == '.' && set->skip_dotdirs)
			return 0;

		if (mail_storage_mailbox_create(dest_storage, dest_name,
						TRUE) < 0) {
			i_error("Mailbox conversion: Couldn't create mailbox "
				"directory %s", dest_name);
			return -1;
		}
		return 0;
	}

	if (strcmp(source_storage->name, "maildir") == 0 &&
	    strcmp(dest_storage->name, "dbox") == 0) {
		if (mailbox_convert_maildir_to_dbox(source_storage,
						    dest_storage,
						    name, dest_name) < 0) {
			i_error("Mailbox conversion failed for mailbox %s",
				name);
			return -1;
		}
		return 0;
	}

	/* First open the source mailbox. If we can't open it, don't create
	   the destination mailbox either. */
	srcbox = mailbox_open(source_storage, name, NULL,
			      MAILBOX_OPEN_READONLY | MAILBOX_OPEN_KEEP_RECENT);
	if (srcbox == NULL) {
		if (set->skip_broken_mailboxes)
			return 0;

		i_error("Mailbox conversion: "
			"Couldn't open source mailbox %s: %s",
			name, storage_error(source_storage));
		return -1;
	}

	/* Create and open the destination mailbox. */
	if (strcmp(dest_name, "INBOX") != 0) {
		if (mail_storage_mailbox_create(dest_storage, dest_name,
						FALSE) < 0) {
			i_error("Mailbox conversion: "
				"Couldn't create mailbox %s: %s",
				dest_name, storage_error(dest_storage));
			mailbox_close(&srcbox);
			return -1;
		}
	}

	destbox = mailbox_open(dest_storage, dest_name, NULL,
			       MAILBOX_OPEN_KEEP_RECENT);
	if (destbox == NULL) {
		i_error("Mailbox conversion: Couldn't open dest mailbox %s: %s",
			dest_name, storage_error(dest_storage));
		mailbox_close(&srcbox);
		return -1;
	}

	if (mailbox_copy_mails(srcbox, destbox, dotlock, &error) < 0) {
		i_error("Mailbox conversion: Couldn't copy mailbox %s: %s",
			mailbox_get_name(srcbox), error);
	}

	mailbox_close(&srcbox);
	mailbox_close(&destbox);
	return ret;
}

static int mailbox_list_copy(struct mail_storage *source_storage,
			     struct mail_namespace *dest_namespaces,
			     struct dotlock *dotlock,
			     const struct convert_settings *set)
{
	struct mailbox_list_iterate_context *iter;
	struct mail_namespace *dest_ns;
	const struct mailbox_info *info;
	int ret = 0;

	dest_ns = mail_namespace_find_inbox(dest_namespaces);
	iter = mailbox_list_iter_init(mail_storage_get_list(source_storage),
				      "*", MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		T_BEGIN {
			ret = mailbox_convert_list_item(source_storage,
							dest_ns->storage,
							info, dotlock, set);
		} T_END;
		if (ret < 0)
			break;

		/* In case there are lots of mailboxes. Also the other touch
		   is done only after 100 mails. */
		(void)file_dotlock_touch(dotlock);
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static int
mailbox_list_copy_subscriptions(struct mail_storage *source_storage,
				struct mail_namespace *dest_namespaces,
				const struct convert_settings *set)
{
	struct mailbox_list_iterate_context *iter;
	struct mail_namespace *dest_ns;
	const struct mailbox_info *info;
	struct mailbox_list *dest_list;
	const char *dest_name;
	int ret = 0;

	dest_ns = mail_namespace_find_inbox(dest_namespaces);
	dest_list = mail_storage_get_list(dest_ns->storage);
	iter = mailbox_list_iter_init(mail_storage_get_list(source_storage),
				      "*", MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		dest_name = mailbox_name_convert(dest_ns->storage,
						 source_storage,
						 set, info->name);
		if (mailbox_list_set_subscribed(dest_list, dest_name,
						TRUE) < 0) {
			ret = -1;
			break;
		}
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

int convert_storage(const char *source_data,
		    struct mail_namespace *dest_namespaces,
		    const struct convert_settings *set)
{
	struct mail_namespace *source_ns, *dest_inbox_ns;
	struct dotlock *dotlock;
        enum mail_storage_flags src_flags;
        enum file_lock_method lock_method;
	const char *path, *error;
	int ret;

	source_ns = mail_namespaces_init_empty(pool_datastack_create());
	dest_inbox_ns = mail_namespace_find_inbox(dest_namespaces);
	src_flags = dest_inbox_ns->storage->flags;
	lock_method = dest_inbox_ns->storage->lock_method;

	src_flags |= MAIL_STORAGE_FLAG_NO_AUTOCREATE;
	if (mail_storage_create(source_ns, NULL, source_data, set->user,
				src_flags, lock_method, &error) < 0) {
		/* No need for conversion. */
		return 0;
	}

        path = t_strconcat(set->home, "/"CONVERT_LOCK_FILENAME, NULL);
	dotlock_settings.use_excl_lock =
		(source_ns->storage->flags &
		 MAIL_STORAGE_FLAG_DOTLOCK_USE_EXCL) != 0;
	dotlock_settings.nfs_flush =
		(source_ns->storage->flags &
		 MAIL_STORAGE_FLAG_NFS_FLUSH_STORAGE) != 0;
	ret = file_dotlock_create(&dotlock_settings, path, 0, &dotlock);
	if (ret <= 0) {
		if (ret == 0)
			i_error("Mailbox conversion: Lock creation timeouted");
		else
			i_error("file_dotlock_create(%s) failed: %m", path);
		return -1;
	}

	/* just in case if another process just had converted the mailbox,
	   reopen the source storage */
	mail_storage_destroy(&source_ns->storage);
	if (mail_storage_create(source_ns, NULL, source_data, set->user,
				src_flags, lock_method, &error) < 0) {
		/* No need for conversion anymore. */
		file_dotlock_delete(&dotlock);
		return 0;
	}

	ret = mailbox_list_copy(source_ns->storage, dest_namespaces,
				dotlock, set);
	if (ret == 0) {
		ret = mailbox_list_copy_subscriptions(source_ns->storage,
						      dest_namespaces, set);
	}

	if (ret == 0) {
		/* all finished. rename the source directory to mark the
		   move as finished. */
		const char *src, *dest;
		bool is_file;

		src = mail_storage_get_mailbox_path(source_ns->storage, "",
						    &is_file);
		if (src != NULL) {
			dest = t_strconcat(src, "-converted", NULL);
			if (rename(src, dest) < 0) {
				i_error("Mailbox conversion: "
					"rename(%s, %s) failed: %m", src, dest);
				/* return success anyway */
			}
		}
		ret = 1;
	}

	file_dotlock_delete(&dotlock);
	mail_namespaces_deinit(&source_ns);
	return ret;
}
