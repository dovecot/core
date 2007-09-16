/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
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

	const char *maildirsize_path;
	uint64_t message_bytes_limit;
	uint64_t message_count_limit;

	uint64_t total_bytes;
	uint64_t total_count;

	int fd;
	time_t recalc_last_stamp;

	unsigned int limits_initialized:1;
	unsigned int master_message_limits:1;
};

struct maildir_list_context {
	struct mail_storage *storage;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;

	string_t *path;
	int state;
};

extern struct quota_backend quota_backend_maildir;

struct dotlock_settings dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 0,
	MEMBER(stale_timeout) 30,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
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
maildir_list_init(struct mail_storage *storage)
{
	struct maildir_list_context *ctx;

	ctx = i_new(struct maildir_list_context, 1);
	ctx->storage = storage;
	ctx->path = str_new(default_pool, 512);
	ctx->iter = mailbox_list_iter_init(mail_storage_get_list(storage), "*",
					   MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	return ctx;
}

static const char *
maildir_list_next(struct maildir_list_context *ctx, time_t *mtime_r)
{
	struct stat st;
	const char *path;
	bool is_file;

	for (;;) {
		if (ctx->state == 0) {
			ctx->info = mailbox_list_iter_next(ctx->iter);
			if (ctx->info == NULL)
				return NULL;
		}

		t_push();
		path = mail_storage_get_mailbox_path(ctx->storage,
						     ctx->info->name,
						     &is_file);
		str_truncate(ctx->path, 0);
		str_append(ctx->path, path);
		str_append(ctx->path, ctx->state == 0 ? "/new" : "/cur");
		t_pop();

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

	*mtime_r = st.st_size;
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
maildirs_check_have_changed(struct mail_storage *storage, time_t latest_mtime)
{
	struct maildir_list_context *ctx;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(storage);
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
	struct dotlock *dotlock;
	string_t *str;
	int fd;

	i_assert(root->fd == -1);

	dotlock_settings.use_excl_lock = getenv("DOTLOCK_USE_EXCL") != NULL;
	fd = file_dotlock_open(&dotlock_settings, path,
			       DOTLOCK_CREATE_FLAG_NONBLOCK, &dotlock);
	if (fd == -1) {
		if (errno == EAGAIN) {
			/* someone's just in the middle of updating it */
			return 1;
		}

		i_error("file_dotlock_open(%s) failed: %m", path);
		return -1;
	}

	str = t_str_new(128);
	if (root->message_bytes_limit != (uint64_t)-1) {
		str_printfa(str, "%lluS",
			    (unsigned long long)root->message_bytes_limit);
	}
	if (root->message_count_limit != (uint64_t)-1) {
		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_printfa(str, "%lluC",
			    (unsigned long long)root->message_count_limit);
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

static int maildirsize_recalculate_storage(struct maildir_quota_root *root,
					   struct mail_storage *storage)
{
	struct maildir_list_context *ctx;
	const char *dir;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(storage);
	while ((dir = maildir_list_next(ctx, &mtime)) != NULL) {
		if (mtime > root->recalc_last_stamp)
			root->recalc_last_stamp = mtime;

		t_push();
		if (maildir_sum_dir(dir, &root->total_bytes,
				    &root->total_count) < 0)
			ret = -1;
		t_pop();
	}
	if (maildir_list_deinit(ctx) < 0)
		ret = -1;

	return ret;
}

static void maildirsize_rebuild_later(struct maildir_quota_root *root)
{
	if (!root->master_message_limits) {
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
	struct mail_storage *const *storages;
	unsigned int i, count;
	int ret = 0;

	maildirsize_recalculate_init(root);

	/* count mails from all storages */
	storages = array_get(&root->root.quota->storages, &count);
	for (i = 0; i < count; i++) {
		if (maildirsize_recalculate_storage(root, storages[i]) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0) {
		/* check if any of the directories have changed */
		for (i = 0; i < count; i++) {
			ret = maildirs_check_have_changed(storages[i],
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

	*bytes_r = (uint64_t)-1;
	*count_r = (uint64_t)-1;

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
	uint64_t message_bytes_limit, message_count_limit;
	long long bytes_diff, total_bytes;
	int count_diff, total_count;
	unsigned int line_count = 0;

	if (*lines == NULL)
		return -1;

	/* first line contains the limits */
	(void)maildir_parse_limit(lines[0], &message_bytes_limit,
				  &message_count_limit);

	if (!root->master_message_limits) {
		/* we don't know the limits, use whatever the file says */
		root->message_bytes_limit = message_bytes_limit;
		root->message_count_limit = message_count_limit;
	} else if (root->message_bytes_limit != message_bytes_limit ||
		   root->message_count_limit != message_count_limit) {
		/* we know the limits and they've changed.
		   the file must be rewritten. */
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
	/* we end always with LF, which shows up as empty last line. there
	   should be no other empty lines */
	if (lines[1] != NULL)
		return -1;

	if (total_bytes < 0 || total_count < 0) {
		/* corrupted */
		return -1;
	}

	if ((uint64_t)total_bytes > root->message_bytes_limit ||
	    (uint64_t)total_count > root->message_count_limit) {
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

static int maildirsize_read(struct maildir_quota_root *root)
{
	char buf[5120+1];
	unsigned int i, size;
	int fd, ret = 0;

	t_push();
	if (root->fd != -1) {
		if (close(root->fd) < 0)
			i_error("close(%s) failed: %m", root->maildirsize_path);
		root->fd = -1;
	}

	fd = nfs_safe_open(root->maildirsize_path, O_RDWR | O_APPEND);
	if (fd == -1) {
		if (errno == ENOENT)
			ret = 0;
		else {
			ret = -1;
			i_error("open(%s) failed: %m", root->maildirsize_path);
		}
		t_pop();
		return ret;
	}

	/* @UNSAFE */
	size = 0;
	while (size < sizeof(buf)-1 &&
	       (ret = read(fd, buf + size, sizeof(buf)-1 - size)) != 0) {
		if (ret < 0) {
			if (errno == ESTALE)
				break;
			i_error("read(%s) failed: %m", root->maildirsize_path);
		}
		size += ret;
	}
	if (ret < 0 || size >= sizeof(buf)-1) {
		/* error / recalculation needed. */
		(void)close(fd);
		t_pop();
		return ret < 0 ? -1 : 0;
	}

	/* file is smaller than 5120 bytes, which means we can use it */
	root->total_bytes = root->total_count = 0;

	/* skip the last line if there's no LF at the end. Remove the last LF
	   so we don't get one empty line in the strsplit. */
	while (size > 0 && buf[size-1] != '\n') size--;
	if (size > 0) size--;
	buf[size] = '\0';

	/* If there are any NUL bytes, the file is broken. */
	for (i = 0; i < size; i++) {
		if (buf[i] == '\0')
			break;
	}

	if (i == size &&
	    maildirsize_parse(root, fd, t_strsplit(buf, "\n")) > 0) {
		root->fd = fd;
		ret = 1;
	} else {
		/* broken file / need recalculation */
		(void)close(fd);
		root->fd = -1;
		ret = 0;
	}
	t_pop();
	return ret;
}

static void maildirquota_init_limits(struct maildir_quota_root *root)
{
	root->limits_initialized = TRUE;

	if (root->root.default_rule.bytes_limit != 0 ||
	    root->root.default_rule.count_limit != 0) {
		root->master_message_limits = TRUE;
		root->message_bytes_limit = root->root.default_rule.bytes_limit;
		root->message_count_limit = root->root.default_rule.count_limit;
	}
}

static int maildirquota_refresh(struct maildir_quota_root *root)
{
	int ret;

	if (!root->limits_initialized)
		maildirquota_init_limits(root);

	ret = maildirsize_read(root);
	if (ret == 0) {
		if (root->message_bytes_limit == (uint64_t)-1 &&
		    root->message_count_limit == (uint64_t)-1) {
			/* no quota */
			return 0;
		}

		ret = maildirsize_recalculate(root);
	}
	return ret < 0 ? -1 : 0;
}

static int maildirsize_update(struct maildir_quota_root *root,
			      int count_diff, int64_t bytes_diff)
{
	const char *str;
	int ret = 0;

	if (count_diff == 0 && bytes_diff == 0)
		return 0;

	t_push();

	/* We rely on O_APPEND working in here. That isn't NFS-safe, but it
	   isn't necessarily that bad because the file is recreated once in
	   a while, and sooner if corruption causes calculations to go
	   over quota. This is also how Maildir++ spec specifies it should be
	   done.. */
	str = t_strdup_printf("%lld %d\n", (long long)bytes_diff, count_diff);
	if (write_full(root->fd, str, strlen(str)) < 0) {
		ret = -1;
		if (errno == ESTALE) {
			/* deleted/replaced already, ignore */
		} else {
			i_error("write_full(%s) failed: %m",
				root->maildirsize_path);
		}
	}
	t_pop();
	return ret;
}

static struct quota_root *maildir_quota_alloc(void)
{
	struct maildir_quota_root *root;

	root = i_new(struct maildir_quota_root, 1);
	root->fd = -1;
	root->message_bytes_limit = (uint64_t)-1;
	root->message_count_limit = (uint64_t)-1;
	return &root->root;
}

static void maildir_quota_deinit(struct quota_root *_root)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	if (root->fd != -1)
		(void)close(root->fd);
	i_free(root);
}

static bool
maildir_quota_parse_rule(struct quota_root *root ATTR_UNUSED,
			 struct quota_rule *rule,
			 const char *str, const char **error_r)
{
	uint64_t bytes, count;

	if (!maildir_parse_limit(str, &bytes, &count)) {
		*error_r = "Invalid Maildir++ quota rule";
		return FALSE;
	}

	rule->bytes_limit = bytes;
	rule->count_limit = count;
	return TRUE;
}

static void
maildir_quota_root_storage_added(struct quota_root *_root,
				 struct mail_storage *storage)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	const char *control_dir;

	if (root->maildirsize_path != NULL)
		return;

	control_dir = mail_storage_get_mailbox_control_dir(storage, "");
	root->maildirsize_path =
		p_strconcat(_root->pool, control_dir,
			    "/"MAILDIRSIZE_FILENAME, NULL);
}

static void
maildir_quota_storage_added(struct quota *quota,
			    struct mail_storage *_storage)
{
	struct maildir_storage *storage =
		(struct maildir_storage *)_storage;
	struct quota_root **roots;
	unsigned int i, count;

	if (strcmp(_storage->name, "maildir") != 0)
		return;

	roots = array_get_modifiable(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->backend.name == quota_backend_maildir.name)
			maildir_quota_root_storage_added(roots[i], _storage);
	}

	/* For newly generated filenames add ,S=size. */
	storage->save_size_in_filename = TRUE;
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
			   uint64_t *value_r, uint64_t *limit  ATTR_UNUSED)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	if (maildirquota_refresh(root) < 0)
		return -1;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*value_r = root->total_bytes;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*value_r = root->total_count;
	else
		return 0;
	return 1;
}

static int
maildir_quota_update(struct quota_root *_root,
		     struct quota_transaction_context *ctx)
{
	struct maildir_quota_root *root =
		(struct maildir_quota_root *) _root;

	if (root->fd == -1 || ctx->recalculate ||
	    maildirsize_update(root, ctx->count_used, ctx->bytes_used) < 0)
		maildirsize_rebuild_later(root);

	return 0;
}

struct quota_backend quota_backend_maildir = {
	"maildir",

	{
		maildir_quota_alloc,
		NULL,
		maildir_quota_deinit,
		maildir_quota_parse_rule,
		maildir_quota_storage_added,
		maildir_quota_root_get_resources,
		maildir_quota_get_resource,
		maildir_quota_update
	}
};
