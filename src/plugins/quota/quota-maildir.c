/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "nfs-workarounds.h"
#include "safe-mkstemp.h"
#include "mkdir-parents.h"
#include "read-full.h"
#include "write-full.h"
#include "str.h"
#include "settings.h"
#include "maildir-storage.h"
#include "mailbox-list-private.h"
#include "quota-private.h"

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILDIRSIZE_FILENAME "maildirsize"
#define MAILDIRSIZE_STALE_SECS (60*15)

struct maildir_quota_root {
	struct quota_root root;

	struct mail_namespace *maildirsize_ns;
	const char *maildirsize_path;

	uint64_t total_bytes;
	uint64_t total_count;

	int fd;
	time_t recalc_last_stamp;
	off_t last_size;

	bool limits_initialized:1;
};

struct maildir_list_context {
	struct mailbox_list *list;
	struct maildir_quota_root *root;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;

	string_t *path;
	int state;
};

extern struct quota_backend quota_backend_maildir;

static struct dotlock_settings dotlock_settings = {
	.timeout = 0,
	.stale_timeout = 30
};

static int maildir_sum_dir(const char *dir, uint64_t *total_bytes,
			   uint64_t *total_count, const char **error_r)
{
	DIR *dirp;
	struct dirent *dp;
	string_t *path;
	const char *p;
	size_t len;
	uoff_t num;
	int ret = 0;

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno == ENOENT || errno == ESTALE)
			return 0;
		*error_r = t_strdup_printf("opendir(%s) failed: %m", dir);
		return -1;
	}

	path = t_str_new(256);
	str_append(path, dir);
	str_append_c(path, '/');

	len = str_len(path);
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.' &&
		    (dp->d_name[1] == '\0' || dp->d_name[1] == '.'))
			continue;

		p = strstr(dp->d_name, ",S=");
		num = UOFF_T_MAX;
		if (p != NULL) {
			/* ,S=nnnn[:,] */
			p += 3;
			for (num = 0; *p >= '0' && *p <= '9'; p++)
				num = num * 10 + (*p - '0');

			if (*p != ':' && *p != '\0' && *p != ',') {
				/* not in expected format, fallback to stat() */
				num = UOFF_T_MAX;
			} else {
				*total_bytes += num;
				*total_count += 1;
			}
		}
		if (num == UOFF_T_MAX) {
			struct stat st;

			str_truncate(path, len);
			str_append(path, dp->d_name);
			if (stat(str_c(path), &st) == 0) {
				*total_bytes += st.st_size;
				*total_count += 1;
			} else if (errno != ENOENT && errno != ESTALE) {
				*error_r = t_strdup_printf(
					"stat(%s) failed: %m", str_c(path));
				ret = -1;
			}
		}
	}

	if (closedir(dirp) < 0) {
		*error_r = t_strdup_printf("closedir(%s) failed: %m", dir);
		return -1;
	}
	return ret;
}

static struct maildir_list_context *
maildir_list_init(struct maildir_quota_root *root, struct mailbox_list *list)
{
	struct maildir_list_context *ctx;

	ctx = i_new(struct maildir_list_context, 1);
	ctx->root = root;
	ctx->path = str_new(default_pool, 512);
	ctx->list = list;
	ctx->iter = mailbox_list_iter_init(list, "*",
					   MAILBOX_LIST_ITER_SKIP_ALIASES |
					   MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	return ctx;
}

static bool maildir_set_next_path(struct maildir_list_context *ctx)
{
	const char *path, *storage_name;

	str_truncate(ctx->path, 0);

	storage_name = mailbox_list_get_storage_name(
				ctx->info->ns->list, ctx->info->vname);
	if (mailbox_list_get_path(ctx->list, storage_name,
					MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&path) > 0) {
		str_append(ctx->path, path);
		str_append(ctx->path, ctx->state == 0 ?
				"/new" : "/cur");
	}

	return str_len(ctx->path) > 0;
}

static const char *
maildir_list_next(struct maildir_list_context *ctx, time_t *mtime_r)
{
	struct stat st;

	for (;;) {
		if (ctx->state == 0) {
			ctx->info = mailbox_list_iter_next(ctx->iter);
			if (ctx->info == NULL)
				return NULL;

			const struct quota_root_settings *set;
			bool quota_ignore = FALSE;
			const char *error;
			struct event *event =
				mail_storage_mailbox_create_event(
					ctx->root->root.backend.event,
					ctx->info->ns->list, ctx->info->vname);
			if (settings_get(event, &quota_root_setting_parser_info,
					 0, &set, &error) < 0)
				e_error(event, "%s", error);
			else {
				quota_ignore = set->quota_ignore;
				settings_free(set);
			}
			event_unref(&event);

			if (quota_ignore) {
				/* mailbox not included in quota */
				continue;
			}
		}

		if (!maildir_set_next_path(ctx)) {
			ctx->state = 0;
			continue;
		}

		if (++ctx->state == 2)
			ctx->state = 0;

		if (stat(str_c(ctx->path), &st) == 0)
			break;
		/* ignore if the directory got lost, stale or if it was
		   actually a file and not a directory */
		if (errno != ENOENT && errno != ESTALE && errno != ENOTDIR) {
			e_error(ctx->root->root.backend.event,
				"stat(%s) failed: %m", str_c(ctx->path));
			ctx->state = 0;
		}
	}

	*mtime_r = st.st_mtime;
	return str_c(ctx->path);
}

static int maildir_list_deinit(struct maildir_list_context *ctx,
			       const char **error_r)
{
	int ret = mailbox_list_iter_deinit(&ctx->iter);
	if (ret < 0)
		*error_r = t_strdup_printf(
			"Listing mailboxes failed: %s",
			mailbox_list_get_last_internal_error(ctx->list, NULL));

	str_free(&ctx->path);
	i_free(ctx);
	return ret;
}

static int
maildirs_check_have_changed(struct maildir_quota_root *root,
			    struct mail_namespace *ns, time_t latest_mtime,
			    const char **error_r)
{
	struct maildir_list_context *ctx;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(root, ns->list);
	while (maildir_list_next(ctx, &mtime) != NULL) {
		if (mtime > latest_mtime) {
			ret = 1;
			break;
		}
	}
	if (maildir_list_deinit(ctx, error_r) < 0)
		return -1;
	return ret;
}

static int maildirsize_write(struct maildir_quota_root *root, const char *path)
{
	struct quota_root *_root = &root->root;
	struct mail_namespace *inbox_ns;
	struct mailbox_permissions perm;
	const char *p, *dir;
	string_t *str, *temp_path;
	int fd;

	i_assert(root->fd == -1);

	/* figure out what permissions we should use for maildirsize.
	   use the inbox namespace's permissions. */
	inbox_ns = mail_namespace_find_inbox(root->root.quota->user->namespaces);
	mailbox_list_get_root_permissions(inbox_ns->list, &perm);

	dotlock_settings.use_excl_lock =
		inbox_ns->list->mail_set->dotlock_use_excl;
	dotlock_settings.nfs_flush =
		inbox_ns->list->mail_set->mail_nfs_storage;

	temp_path = t_str_new(128);
	str_append(temp_path, path);
	fd = safe_mkstemp_hostpid_group(temp_path, perm.file_create_mode,
					perm.file_create_gid,
					perm.file_create_gid_origin);
	if (fd == -1 && errno == ENOENT) {
		/* the control directory doesn't exist yet? create it */
		p = strrchr(path, '/');
		dir = t_strdup_until(path, p);
		if (mkdir_parents_chgrp(dir, perm.dir_create_mode,
					perm.file_create_gid,
					perm.file_create_gid_origin) < 0 &&
		    errno != EEXIST) {
			e_error(root->root.backend.event,
				"mkdir_parents(%s) failed: %m", dir);
			return -1;
		}
		fd = safe_mkstemp_hostpid_group(temp_path,
						perm.file_create_mode,
						perm.file_create_gid,
						perm.file_create_gid_origin);
	}
	if (fd == -1) {
		e_error(root->root.backend.event,
			"safe_mkstemp(%s) failed: %m", path);
		return -1;
	}

	str = t_str_new(128);
	/* if we have no limits, write 0S instead of an empty line */
	if (_root->bytes_limit != 0 || _root->count_limit == 0) {
		str_printfa(str, "%"PRId64"S", _root->bytes_limit);
	}
	if (_root->count_limit != 0) {
		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_printfa(str, "%"PRIu64"C", _root->count_limit);
	}
	str_printfa(str, "\n%"PRIu64" %"PRIu64"\n",
		    root->total_bytes, root->total_count);
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		e_error(root->root.backend.event,
			"write_full(%s) failed: %m", str_c(temp_path));
		i_close_fd(&fd);
		i_unlink(str_c(temp_path));
		return -1;
	}
	i_close_fd(&fd);

	if (rename(str_c(temp_path), path) < 0) {
		e_error(root->root.backend.event,
			"rename(%s, %s) failed: %m", str_c(temp_path), path);
		i_unlink_if_exists(str_c(temp_path));
		return -1;
	}
	return 0;
}

static void maildirsize_recalculate_init(struct maildir_quota_root *root)
{
	root->total_bytes = root->total_count = 0;
	root->recalc_last_stamp = 0;
}

static int maildirsize_recalculate_namespace(struct maildir_quota_root *root,
					     struct mail_namespace *ns,
					     const char **error_r)
{
	struct maildir_list_context *ctx;
	const char *dir;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(root, ns->list);
	while ((dir = maildir_list_next(ctx, &mtime)) != NULL) {
		if (mtime > root->recalc_last_stamp)
			root->recalc_last_stamp = mtime;

		if (maildir_sum_dir(dir, &root->total_bytes,
				    &root->total_count, error_r) < 0)
			ret = -1;
	}
	if (maildir_list_deinit(ctx, error_r) < 0)
		ret = -1;

	return ret;
}

static void maildirsize_rebuild_later(struct maildir_quota_root *root)
{
	if (unlink(root->maildirsize_path) < 0 &&
	    errno != ENOENT && errno != ESTALE)
		e_error(root->root.backend.event,
			"unlink(%s) failed: %m", root->maildirsize_path);
}

static int maildirsize_recalculate_finish(struct maildir_quota_root *root,
					  int ret, const char **error_r)
{
	if (ret == 0) {
		/* maildir didn't change, we can write the maildirsize file */
		if ((ret = maildirsize_write(root, root->maildirsize_path)) < 0)
			*error_r = "failed to write maildirsize";
	}
	if (ret != 0)
		maildirsize_rebuild_later(root);

	return ret;
}

static int maildirsize_recalculate(struct maildir_quota_root *root,
				   const char **error_r)
{
	struct mail_namespace *const *namespaces;
	struct event_reason *reason;
	unsigned int i, count;
	int ret = 0;

	reason = event_reason_begin("quota:recalculate");
	maildirsize_recalculate_init(root);

	/* count mails from all namespaces */
	namespaces = array_get(&root->root.namespaces, &count);
	for (i = 0; i < count; i++) {
		if (maildirsize_recalculate_namespace(root, namespaces[i], error_r) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0) {
		/* check if any of the directories have changed */
		for (i = 0; i < count; i++) {
			ret = maildirs_check_have_changed(root, namespaces[i],
						root->recalc_last_stamp,
						error_r);
			if (ret != 0)
				break;
		}
	}

	ret = maildirsize_recalculate_finish(root, ret, error_r);
	event_reason_end(&reason);
	return ret;
}

static bool
maildir_parse_limit(const char *str, uint64_t *bytes_r, uint64_t *count_r)
{
	const char *const *limit;
	unsigned long long value;
	const char *pos;
	bool ret = TRUE;

	*bytes_r = 0;
	*count_r = 0;

	/* 0 values mean unlimited */
	for (limit = t_strsplit(str, ","); *limit != NULL; limit++) {
		if (str_parse_ullong(*limit, &value, &pos) < 0) {
			ret = FALSE;
			continue;
		}
		if (pos[0] != '\0' && pos[1] == '\0') {
			switch (pos[0]) {
			case 'C':
				if (value != 0)
					*count_r = value;
				break;
			case 'S':
				if (value != 0)
					*bytes_r = value;
				break;
			default:
				ret = FALSE;
				break;
			}
		} else {
			ret = FALSE;
		}
	}
	return ret;
}

static int maildirsize_parse(struct maildir_quota_root *root,
			     int fd, const char *const *lines)
{
	struct quota_root *_root = &root->root;
	uint64_t message_bytes_limit, message_count_limit;
	long long bytes_diff, total_bytes;
	int count_diff, total_count;
	unsigned int line_count = 0;

	if (*lines == NULL)
		return -1;

	/* first line contains the limits */
	(void)maildir_parse_limit(lines[0], &message_bytes_limit,
				  &message_count_limit);

	/* truncate too high limits to signed 64bit int range */
	if (message_bytes_limit >= (1ULL << 63))
		message_bytes_limit = (1ULL << 63) - 1;
	if (message_count_limit >= (1ULL << 63))
		message_count_limit = (1ULL << 63) - 1;

	if (root->root.bytes_limit != (int64_t)message_bytes_limit ||
	    root->root.count_limit != (int64_t)message_count_limit) {
		/* the limits have changed. the file must be rewritten. */
		return 0;
	}

	if (*lines == NULL) {
		/* no quota lines. rebuild it. */
		return 0;
	}

	/* rest of the lines contains <bytes> <count> diffs */
	total_bytes = 0; total_count = 0;
	for (lines++; *lines != NULL; lines++, line_count++) {
		if (sscanf(*lines, "%lld %d", &bytes_diff, &count_diff) != 2)
			return -1;

		total_bytes += bytes_diff;
		total_count += count_diff;
	}

	if (total_bytes < 0 || total_count < 0) {
		/* corrupted */
		return -1;
	}

	if ((total_bytes > _root->bytes_limit && _root->bytes_limit != 0) ||
	    (total_count > _root->count_limit && _root->count_limit != 0)) {
		/* we're over quota. don't trust these values if the file
		   contains more than the initial summary line, or if the file
		   is older than 15 minutes. */
		struct stat st;

		if (line_count > 1)
			return 0;

		if (fstat(fd, &st) < 0 ||
		    st.st_mtime < ioloop_time - MAILDIRSIZE_STALE_SECS)
			return 0;
	}
	root->total_bytes = (uint64_t)total_bytes;
	root->total_count = (uint64_t)total_count;
	return 1;
}

static int maildirsize_open(struct maildir_quota_root *root,
			    const char **error_r)
{
	i_close_fd_path(&root->fd, root->maildirsize_path);

	root->fd = nfs_safe_open(root->maildirsize_path, O_RDWR | O_APPEND);
	if (root->fd == -1) {
		if (errno == ENOENT)
			return 0;
		*error_r = t_strdup_printf(
			"open(%s) failed: %m", root->maildirsize_path);
		return -1;
	}
	return 1;
}

static bool maildirsize_has_changed(struct maildir_quota_root *root)
{
	struct stat st1, st2;

	if (dotlock_settings.nfs_flush) {
		nfs_flush_file_handle_cache(root->maildirsize_path);
		nfs_flush_attr_cache_unlocked(root->maildirsize_path);
	}

	if (root->fd == -1)
		return TRUE;

	if (stat(root->maildirsize_path, &st1) < 0)
		return TRUE;
	if (fstat(root->fd, &st2) < 0)
		return TRUE;

	return root->last_size != st2.st_size || st1.st_ino != st2.st_ino ||
		!CMP_DEV_T(st1.st_dev, st2.st_dev);
}

static int maildirsize_read(struct maildir_quota_root *root, bool *retry,
			    const char **error_r)
{
	char buf[5120+1];
	unsigned int i, size;
	bool retry_estale = *retry;
	int ret;

	*retry = FALSE;

	if (!maildirsize_has_changed(root))
		return 1;

	if ((ret = maildirsize_open(root, error_r)) <= 0)
		return ret;

	/* @UNSAFE */
	size = 0;
	while ((ret = read(root->fd, buf + size, sizeof(buf)-1 - size)) != 0) {
		if (ret < 0) {
			if (errno == ESTALE && retry_estale) {
				*retry = TRUE;
				break;
			}
			*error_r = t_strdup_printf(
				"read(%s) failed: %m", root->maildirsize_path);
			break;
		}
		size += ret;
		if (size >= sizeof(buf)-1) {
			/* we'll need to recalculate the quota */
			break;
		}
	}

	/* try to use the file even if we ran into some error. if we don't have
	   forced limits, we'll need to read the header to get them */
	root->total_bytes = root->total_count = 0;
	root->last_size = size;

	/* skip the last line if there's no LF at the end. Remove the last LF
	   so we don't get one empty line in the strsplit. */
	while (size > 0 && buf[size-1] != '\n') size--;
	if (size > 0) size--;
	buf[size] = '\0';

	if (ret < 0 && size == 0) {
		/* the read failed and there's no usable header, fail. */
		i_close_fd(&root->fd);
		return -1;
	}

	/* If there are any NUL bytes, the file is broken. */
	for (i = 0; i < size; i++) {
		if (buf[i] == '\0')
			break;
	}

	if (i == size &&
	    maildirsize_parse(root, root->fd, t_strsplit(buf, "\n")) > 0 &&
	    ret == 0)
		ret = 1;
	else {
		/* broken file / need recalculation */
		i_close_fd(&root->fd);
		ret = 0;
	}
	return ret;
}

static bool maildirquota_limits_init(struct maildir_quota_root *root)
{
	struct mailbox_list *list;
	struct mail_storage *storage;
	const char *control_dir;

	if (root->limits_initialized)
		return root->maildirsize_path != NULL;
	root->limits_initialized = TRUE;

	if (root->maildirsize_ns == NULL) {
		i_assert(root->maildirsize_path == NULL);
		return FALSE;
	}

	list = root->maildirsize_ns->list;
	const char *vname = "";
	if (mailbox_list_get_storage(&list, &vname, 0, &storage) == 0 &&
	    strcmp(storage->name, MAILDIR_STORAGE_NAME) != 0) {
		/* non-maildir namespace, skip */
		if ((storage->class_flags &
		     MAIL_STORAGE_CLASS_FLAG_NOQUOTA) == 0) {
			e_warning(root->root.backend.event,
				  "Namespace %s is not Maildir, "
				  "skipping for Maildir++ quota",
				  root->maildirsize_ns->set->name);
		}
		root->maildirsize_path = NULL;
		return FALSE;
	}
	if (root->maildirsize_path == NULL) {
		if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_CONTROL,
						&control_dir))
			i_unreached();
		root->maildirsize_path =
			p_strconcat(root->root.pool, control_dir,
				    "/"MAILDIRSIZE_FILENAME, NULL);
	}
	return TRUE;
}

static int maildirquota_read_limits(struct maildir_quota_root *root,
				    const char **error_r)
{
	bool retry = TRUE;
	int ret, n = 0;

	if (!maildirquota_limits_init(root))
		return 1;

	do {
		if (n == NFS_ESTALE_RETRY_COUNT)
			retry = FALSE;
		ret = maildirsize_read(root, &retry, error_r);
		n++;
	} while (ret == -1 && retry);
	return ret;
}

static int
maildirquota_refresh(struct maildir_quota_root *root, bool *recalculated_r,
		     const char **error_r)
{
	int ret;

	*recalculated_r = FALSE;

	ret = maildirquota_read_limits(root, error_r);
	if (ret == 0) {
		ret = maildirsize_recalculate(root, error_r);
		if (ret == 0)
			*recalculated_r = TRUE;
	}
	return ret < 0 ? -1 : 0;
}

static int maildirsize_update(struct maildir_quota_root *root,
			      int count_diff, int64_t bytes_diff)
{
	char str[MAX_INT_STRLEN * 2 + 2];
	int ret = 0;

	if (count_diff == 0 && bytes_diff == 0)
		return 0;

	/* We rely on O_APPEND working in here. That isn't NFS-safe, but it
	   isn't necessarily that bad because the file is recreated once in
	   a while, and sooner if corruption causes calculations to go
	   over quota. This is also how Maildir++ spec specifies it should be
	   done.. */
	if (i_snprintf(str, sizeof(str), "%lld %d\n",
		       (long long)bytes_diff, count_diff) < 0)
		i_unreached();
	if (write_full(root->fd, str, strlen(str)) < 0) {
		ret = -1;
		if (errno == ESTALE) {
			/* deleted/replaced already, ignore */
		} else {
			e_error(root->root.backend.event,
				"write_full(%s) failed: %m",
				root->maildirsize_path);
		}
	} else {
		/* close the file to force a flush with NFS */
		if (close(root->fd) < 0) {
			ret = -1;
			if (errno != ESTALE)
				e_error(root->root.backend.event,
					"close(%s) failed: %m", root->maildirsize_path);
		}
		root->fd = -1;
	}
	return ret;
}

static struct quota_root *maildir_quota_alloc(void)
{
	struct maildir_quota_root *root;

	root = i_new(struct maildir_quota_root, 1);
	root->fd = -1;
	return &root->root;
}

static int maildir_quota_init(struct quota_root *_root ATTR_UNUSED,
			      const char **error_r ATTR_UNUSED)
{
	return 0;
}

static void maildir_quota_deinit(struct quota_root *_root)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	i_close_fd(&root->fd);
	i_free(root);
}

static void
maildir_quota_namespace_added(struct quota_root *_root,
			      struct mail_namespace *ns)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	if (root->maildirsize_ns == NULL ||
	    root->maildirsize_ns->type != MAIL_NAMESPACE_TYPE_PRIVATE)
		root->maildirsize_ns = ns;
}

static const char *const *
maildir_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources_both[] = {
		QUOTA_NAME_STORAGE_KILOBYTES,
		QUOTA_NAME_MESSAGES,
		NULL
	};

	return resources_both;
}

static enum quota_get_result
maildir_quota_get_resource(struct quota_root *_root, const char *name,
			   uint64_t *value_r, const char **error_r)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	bool recalculated;
	const char *error;

	if (maildirquota_refresh(root, &recalculated, &error) < 0) {
		*error_r = t_strdup_printf("Failed to get %s: %s", name, error);
		return QUOTA_GET_RESULT_INTERNAL_ERROR;
	}

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0) {
		*value_r = root->total_bytes;
	} else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0) {
		*value_r = root->total_count;
	} else {
		*error_r = QUOTA_UNKNOWN_RESOURCE_ERROR_STRING;
		return QUOTA_GET_RESULT_UNKNOWN_RESOURCE;
	}
	return QUOTA_GET_RESULT_LIMITED;
}

static int
maildir_quota_update(struct quota_root *_root,
		     struct quota_transaction_context *ctx,
		     const char **error_r)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	bool recalculated;
	const char *error;

	if (!maildirquota_limits_init(root)) {
		/* no limits */
		return 0;
	}

	/* even though we don't really care about the limits in here ourself,
	   we do want to make sure the header gets updated if the limits have
	   changed. also this makes sure the maildirsize file is created if
	   it doesn't exist. */
	if (maildirquota_refresh(root, &recalculated, &error) < 0) {
		*error_r = t_strdup_printf(
			"Could not update storage usage data: %s",
			error);
		return -1;
	}

	if (recalculated) {
		/* quota was just recalculated and it already contains the changes
		   we wanted to do. */
	} else if (root->fd == -1) {
		if (maildirsize_recalculate(root, &error) < 0)
			e_error(root->root.backend.event, "%s", error);
	} else if (ctx->recalculate != QUOTA_RECALCULATE_DONT) {
		i_close_fd(&root->fd);
		if (maildirsize_recalculate(root, &error) < 0)
			e_error(root->root.backend.event, "%s", error);
	} else if (maildirsize_update(root, ctx->count_used, ctx->bytes_used) < 0) {
		i_close_fd(&root->fd);
		maildirsize_rebuild_later(root);
	}

	return 0;
}

struct quota_backend quota_backend_maildir = {
	.name = "maildir",
	.use_vsize = FALSE,

	.v = {
		.alloc = maildir_quota_alloc,
		.init = maildir_quota_init,
		.deinit = maildir_quota_deinit,
		.namespace_added = maildir_quota_namespace_added,
		.get_resources = maildir_quota_root_get_resources,
		.get_resource = maildir_quota_get_resource,
		.update = maildir_quota_update,
	}
};
