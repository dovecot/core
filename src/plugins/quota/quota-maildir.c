/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
#include "mkdir-parents.h"
#include "read-full.h"
#include "write-full.h"
#include "str.h"
#include "maildir-storage.h"
#include "quota-private.h"

#include <stdio.h>
#include <stdlib.h>
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

	unsigned int limits_initialized:1;
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
			   uint64_t *total_count)
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
		i_error("opendir(%s) failed: %m", dir);
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
		num = (uoff_t)-1;
		if (p != NULL) {
			/* ,S=nnnn[:,] */
			p += 3;
			for (num = 0; *p >= '0' && *p <= '9'; p++)
				num = num * 10 + (*p - '0');

			if (*p != ':' && *p != '\0' && *p != ',') {
				/* not in expected format, fallback to stat() */
				num = (uoff_t)-1;
			} else {
				*total_bytes += num;
				*total_count += 1;
			}
		}
		if (num == (uoff_t)-1) {
			struct stat st;

			str_truncate(path, len);
			str_append(path, dp->d_name);
			if (stat(str_c(path), &st) == 0) {
				*total_bytes += st.st_size;
				*total_count += 1;
			} else if (errno != ENOENT && errno != ESTALE) {
				i_error("stat(%s) failed: %m", str_c(path));
				ret = -1;
			}
		}
	}

	if (closedir(dirp) < 0) {
		i_error("closedir(%s) failed: %m", dir);
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
					   MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	return ctx;
}

static const char *
maildir_list_next(struct maildir_list_context *ctx, time_t *mtime_r)
{
	struct quota_rule *rule;
	struct stat st;

	for (;;) {
		if (ctx->state == 0) {
			ctx->info = mailbox_list_iter_next(ctx->iter);
			if (ctx->info == NULL)
				return NULL;

			rule = quota_root_rule_find(ctx->root->root.set,
						    ctx->info->name);
			if (rule != NULL && rule->ignore) {
				/* mailbox not included in quota */
				continue;
			}
		}

		T_BEGIN {
			const char *path, *storage_name;

			storage_name = mail_namespace_get_storage_name(
				ctx->info->ns, ctx->info->name);
			path = mailbox_list_get_path(ctx->list, storage_name,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
			str_truncate(ctx->path, 0);
			str_append(ctx->path, path);
			str_append(ctx->path, ctx->state == 0 ?
				   "/new" : "/cur");
		} T_END;

		if (++ctx->state == 2)
			ctx->state = 0;

		if (stat(str_c(ctx->path), &st) == 0)
			break;
		/* ignore if the directory got lost, stale or if it was
		   actually a file and not a directory */
		if (errno != ENOENT && errno != ESTALE && errno != ENOTDIR) {
			i_error("stat(%s) failed: %m", str_c(ctx->path));
			ctx->state = 0;
		}
	}

	*mtime_r = st.st_mtime;
	return str_c(ctx->path);
}

static int maildir_list_deinit(struct maildir_list_context *ctx)
{
	int ret = mailbox_list_iter_deinit(&ctx->iter);

	str_free(&ctx->path);
	i_free(ctx);
	return ret;
}

static int
maildirs_check_have_changed(struct maildir_quota_root *root,
			    struct mail_namespace *ns, time_t latest_mtime)
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
	if (maildir_list_deinit(ctx) < 0)
		return -1;
	return ret;
}

static int maildirsize_write(struct maildir_quota_root *root, const char *path)
{
	const struct mail_storage_settings *set =
		root->maildirsize_ns->mail_set;
	struct quota_root *_root = &root->root;
	struct mail_namespace *const *namespaces;
	unsigned int i, count;
	struct dotlock *dotlock;
	const char *p, *dir, *gid_origin, *dir_gid_origin;
	string_t *str;
	mode_t mode, dir_mode;
	gid_t gid, dir_gid;
	int fd;

	i_assert(root->fd == -1);

	/* figure out what permissions we should use for maildirsize.
	   use the inbox namespace's permissions if possible. */
	mode = 0600; dir_mode = 0700; dir_gid_origin = gid_origin = "default";
	gid = dir_gid = (gid_t)-1;
	namespaces = array_get(&root->root.quota->namespaces, &count);
	i_assert(count > 0);
	for (i = 0; i < count; i++) {
		if ((namespaces[i]->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			mailbox_list_get_permissions(namespaces[i]->list,
						     NULL, &mode, &gid,
						     &gid_origin);
			mailbox_list_get_dir_permissions(namespaces[i]->list,
							 NULL,
							 &dir_mode, &dir_gid,
							 &dir_gid_origin);
			break;
		}
	}

	dotlock_settings.use_excl_lock = set->dotlock_use_excl;
	dotlock_settings.nfs_flush = set->mail_nfs_storage;
	fd = file_dotlock_open_group(&dotlock_settings, path,
				     DOTLOCK_CREATE_FLAG_NONBLOCK,
				     mode, gid, gid_origin, &dotlock);
	if (fd == -1 && errno == ENOENT) {
		/* the control directory doesn't exist yet? create it */
		p = strrchr(path, '/');
		dir = t_strdup_until(path, p);
		if (mkdir_parents_chgrp(dir, dir_mode, dir_gid,
					dir_gid_origin) < 0 &&
		    errno != EEXIST) {
			i_error("mkdir_parents(%s) failed: %m", dir);
			return -1;
		}
		fd = file_dotlock_open_group(&dotlock_settings, path,
					     DOTLOCK_CREATE_FLAG_NONBLOCK,
					     mode, gid, gid_origin, &dotlock);
	}
	if (fd == -1) {
		if (errno == EAGAIN) {
			/* someone's just in the middle of updating it */
			return 1;
		}

		i_error("file_dotlock_open(%s) failed: %m", path);
		return -1;
	}

	str = t_str_new(128);
	/* if we have no limits, write 0S instead of an empty line */
	if (_root->bytes_limit != 0 || _root->count_limit == 0) {
		str_printfa(str, "%lluS",
			    (unsigned long long)_root->bytes_limit);
	}
	if (_root->count_limit != 0) {
		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_printfa(str, "%lluC",
			    (unsigned long long)_root->count_limit);
	}
	str_printfa(str, "\n%llu %llu\n",
		    (unsigned long long)root->total_bytes,
		    (unsigned long long)root->total_count);
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		i_error("write_full(%s) failed: %m", path);
		file_dotlock_delete(&dotlock);
		return -1;
	}

	/* keep the fd open since we might want to update it later */
	if (file_dotlock_replace(&dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) < 0) {
		i_error("file_dotlock_replace(%s) failed: %m", path);
		return -1;
	}
	root->fd = fd;
	return 0;
}

static void maildirsize_recalculate_init(struct maildir_quota_root *root)
{
	root->total_bytes = root->total_count = 0;
	root->recalc_last_stamp = 0;
}

static int maildirsize_recalculate_namespace(struct maildir_quota_root *root,
					     struct mail_namespace *ns)
{
	struct maildir_list_context *ctx;
	const char *dir;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(root, ns->list);
	while ((dir = maildir_list_next(ctx, &mtime)) != NULL) {
		if (mtime > root->recalc_last_stamp)
			root->recalc_last_stamp = mtime;

		T_BEGIN {
			if (maildir_sum_dir(dir, &root->total_bytes,
					    &root->total_count) < 0)
				ret = -1;
		} T_END;
	}
	if (maildir_list_deinit(ctx) < 0)
		ret = -1;

	return ret;
}

static void maildirsize_rebuild_later(struct maildir_quota_root *root)
{
	if (!root->root.set->force_default_rule) {
		/* FIXME: can't unlink(), because the limits would be lost. */
		return;
	}

	if (unlink(root->maildirsize_path) < 0 &&
	    errno != ENOENT && errno != ESTALE)
		i_error("unlink(%s) failed: %m", root->maildirsize_path);
}

static int maildirsize_recalculate_finish(struct maildir_quota_root *root,
					  int ret)
{
	if (ret == 0) {
		/* maildir didn't change, we can write the maildirsize file */
		ret = maildirsize_write(root, root->maildirsize_path);
	}
	if (ret != 0)
		maildirsize_rebuild_later(root);

	return ret;
}

static int maildirsize_recalculate(struct maildir_quota_root *root)
{
	struct mail_namespace *const *namespaces;
	unsigned int i, count;
	int ret = 0;

	maildirsize_recalculate_init(root);

	/* count mails from all namespaces */
	namespaces = array_get(&root->root.quota->namespaces, &count);
	for (i = 0; i < count; i++) {
		if (!quota_root_is_namespace_visible(&root->root, namespaces[i]))
			continue;

		if (maildirsize_recalculate_namespace(root, namespaces[i]) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0) {
		/* check if any of the directories have changed */
		for (i = 0; i < count; i++) {
			if (!quota_root_is_namespace_visible(&root->root,
							   namespaces[i]))
				continue;

			ret = maildirs_check_have_changed(root, namespaces[i],
						root->recalc_last_stamp);
			if (ret != 0)
				break;
		}
	}

	return maildirsize_recalculate_finish(root, ret);
}

static bool
maildir_parse_limit(const char *str, uint64_t *bytes_r, uint64_t *count_r)
{
	const char *const *limit;
	unsigned long long value;
	char *pos;
	bool ret = TRUE;

	*bytes_r = 0;
	*count_r = 0;

	/* 0 values mean unlimited */
	for (limit = t_strsplit(str, ","); *limit != NULL; limit++) {
		value = strtoull(*limit, &pos, 10);
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

	if (root->root.bytes_limit == (int64_t)message_bytes_limit &&
	    root->root.count_limit == (int64_t)message_count_limit) {
		/* limits haven't changed */
	} else if (root->root.set->force_default_rule) {
		/* we know the limits and they've changed.
		   the file must be rewritten. */
		return 0;
	} else {
		/* we're using limits from the file. */
		root->root.bytes_limit = message_bytes_limit;
		root->root.count_limit = message_count_limit;
		quota_root_recalculate_relative_rules(root->root.set,
						      message_bytes_limit,
						      message_count_limit);
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

static int maildirsize_open(struct maildir_quota_root *root)
{
	if (root->fd != -1) {
		if (close(root->fd) < 0)
			i_error("close(%s) failed: %m", root->maildirsize_path);
	}

	root->fd = nfs_safe_open(root->maildirsize_path, O_RDWR | O_APPEND);
	if (root->fd == -1) {
		if (errno == ENOENT)
			return 0;
		i_error("open(%s) failed: %m", root->maildirsize_path);
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

static int maildirsize_read(struct maildir_quota_root *root)
{
	char buf[5120+1];
	unsigned int i, size;
	int ret;

	if (!maildirsize_has_changed(root))
		return 1;

	if ((ret = maildirsize_open(root)) <= 0)
		return ret;

	/* @UNSAFE */
	size = 0;
	while ((ret = read(root->fd, buf + size, sizeof(buf)-1 - size)) != 0) {
		if (ret < 0) {
			if (errno == ESTALE)
				break;
			i_error("read(%s) failed: %m", root->maildirsize_path);
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
		(void)close(root->fd);
		root->fd = -1;
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
		(void)close(root->fd);
		root->fd = -1;
		ret = 0;
	}
	return ret;
}

static bool maildirquota_limits_init(struct maildir_quota_root *root)
{
	struct mailbox_list *list;
	struct mail_storage *storage;
	const char *name = "";

	if (root->limits_initialized)
		return root->maildirsize_path != NULL;
	root->limits_initialized = TRUE;

	if (root->maildirsize_ns == NULL) {
		i_assert(root->maildirsize_path == NULL);
		return FALSE;
	}
	i_assert(root->maildirsize_path != NULL);

	list = root->maildirsize_ns->list;
	if (mailbox_list_get_storage(&list, &name, &storage) == 0 &&
	    strcmp(storage->name, MAILDIR_STORAGE_NAME) != 0) {
		/* non-maildir namespace, skip */
		if ((storage->class_flags &
		     MAIL_STORAGE_CLASS_FLAG_NOQUOTA) == 0) {
			i_warning("quota: Namespace '%s' is not Maildir, "
				  "skipping for Maildir++ quota",
				  root->maildirsize_ns->prefix);
		}
		root->maildirsize_path = NULL;
		return FALSE;
	}
	return TRUE;
}

static int maildirquota_read_limits(struct maildir_quota_root *root)
{
	int ret;

	if (!maildirquota_limits_init(root))
		return 1;

	T_BEGIN {
		ret = maildirsize_read(root);
	} T_END;
	return ret;
}

static int
maildirquota_refresh(struct maildir_quota_root *root, bool *recalculated_r)
{
	int ret;

	*recalculated_r = FALSE;

	ret = maildirquota_read_limits(root);
	if (ret == 0) {
		if (root->root.bytes_limit == 0 &&
		    root->root.count_limit == 0 &&
		    root->root.set->default_rule.bytes_limit == 0 &&
		    root->root.set->default_rule.count_limit == 0) {
			/* no quota */
			if (!root->root.set->force_default_rule)
				return 0;
			/* explicitly specified 0 as quota. keep the quota
			   updated even if it's not enforced. */
		}

		ret = maildirsize_recalculate(root);
		if (ret == 0)
			*recalculated_r = TRUE;
	}
	return ret < 0 ? -1 : 0;
}

static int maildirsize_update(struct maildir_quota_root *root,
			      int count_diff, int64_t bytes_diff)
{
	char str[MAX_INT_STRLEN*2 + 2];
	int ret = 0;

	if (count_diff == 0 && bytes_diff == 0)
		return 0;

	/* We rely on O_APPEND working in here. That isn't NFS-safe, but it
	   isn't necessarily that bad because the file is recreated once in
	   a while, and sooner if corruption causes calculations to go
	   over quota. This is also how Maildir++ spec specifies it should be
	   done.. */
	i_snprintf(str, sizeof(str), "%lld %d\n",
		   (long long)bytes_diff, count_diff);
	if (write_full(root->fd, str, strlen(str)) < 0) {
		ret = -1;
		if (errno == ESTALE) {
			/* deleted/replaced already, ignore */
		} else {
			i_error("write_full(%s) failed: %m",
				root->maildirsize_path);
		}
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

static int maildir_quota_init(struct quota_root *_root, const char *args)
{
	const char *const *tmp;

	if (args == NULL)
		return 0;

	for (tmp = t_strsplit(args, ":"); *tmp != NULL; tmp++) {
		if (strcmp(*tmp, "noenforcing") == 0)
			_root->no_enforcing = TRUE;
		else if (strcmp(*tmp, "ignoreunlimited") == 0)
			_root->disable_unlimited_tracking = TRUE;
		else if (strncmp(*tmp, "ns=", 3) == 0)
			_root->ns_prefix = p_strdup(_root->pool, *tmp + 3);
		else {
			i_error("maildir quota: Invalid parameter: %s", *tmp);
			return -1;
		}
	}
	return 0;
}

static void maildir_quota_deinit(struct quota_root *_root)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	if (root->fd != -1)
		(void)close(root->fd);
	i_free(root);
}

static bool
maildir_quota_parse_rule(struct quota_root_settings *root_set ATTR_UNUSED,
			 struct quota_rule *rule,
			 const char *str, const char **error_r)
{
	uint64_t bytes, count;

	if (strcmp(str, "NOQUOTA") == 0) {
		bytes = 0;
		count = 0;
	} else if (!maildir_parse_limit(str, &bytes, &count)) {
		*error_r = "Invalid Maildir++ quota rule";
		return FALSE;
	}

	rule->bytes_limit = bytes;
	rule->count_limit = count;
	return TRUE;
}

static int maildir_quota_init_limits(struct quota_root *_root)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	return maildirquota_read_limits(root) < 0 ? -1 : 0;
}

static void
maildir_quota_root_namespace_added(struct quota_root *_root,
				   struct mail_namespace *ns)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	const char *control_dir;

	if (root->maildirsize_path != NULL)
		return;

	control_dir = mailbox_list_get_path(ns->list, NULL,
					    MAILBOX_LIST_PATH_TYPE_CONTROL);
	root->maildirsize_ns = ns;
	root->maildirsize_path =
		p_strconcat(_root->pool, control_dir,
			    "/"MAILDIRSIZE_FILENAME, NULL);
}

static void
maildir_quota_namespace_added(struct quota *quota, struct mail_namespace *ns)
{
	struct quota_root **roots;
	unsigned int i, count;

	roots = array_get_modifiable(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->backend.name == quota_backend_maildir.name &&
		    ((roots[i]->ns_prefix == NULL &&
		      ns->type == NAMESPACE_PRIVATE) || roots[i]->ns == ns))
			maildir_quota_root_namespace_added(roots[i], ns);
	}
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

static int
maildir_quota_get_resource(struct quota_root *_root, const char *name,
			   uint64_t *value_r)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	bool recalculated;

	if (maildirquota_refresh(root, &recalculated) < 0)
		return -1;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0) {
		*value_r = root->total_bytes;
	} else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0) {
		*value_r = root->total_count;
	} else
		return 0;
	return 1;
}

static int
maildir_quota_update(struct quota_root *_root,
		     struct quota_transaction_context *ctx)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	bool recalculated;

	if (!maildirquota_limits_init(root)) {
		/* no limits */
		return 0;
	}

	/* even though we don't really care about the limits in here ourself,
	   we do want to make sure the header gets updated if the limits have
	   changed. also this makes sure the maildirsize file is created if
	   it doesn't exist. */
	if (maildirquota_refresh(root, &recalculated) < 0)
		return -1;

	if (recalculated) {
		/* quota was just recalculated and it already contains the changes
		   we wanted to do. */
	} else if (root->fd == -1)
		(void)maildirsize_recalculate(root);
	else if (ctx->recalculate) {
		(void)close(root->fd);
		root->fd = -1;
		(void)maildirsize_recalculate(root);
	} else if (maildirsize_update(root, ctx->count_used, ctx->bytes_used) < 0)
		maildirsize_rebuild_later(root);

	return 0;
}

struct quota_backend quota_backend_maildir = {
	"maildir",

	{
		maildir_quota_alloc,
		maildir_quota_init,
		maildir_quota_deinit,
		maildir_quota_parse_rule,
		maildir_quota_init_limits,
		maildir_quota_namespace_added,
		maildir_quota_root_get_resources,
		maildir_quota_get_resource,
		maildir_quota_update,
		NULL
	}
};
