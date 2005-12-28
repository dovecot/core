/* Copyright (C) 2005 Timo Sirainen */

/* Quota reporting based on simply summing sizes of all files in mailbox
   together. */

#include "lib.h"
#include "str.h"
#include "quota-private.h"

#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

struct dirsize_quota {
	struct quota quota;

	pool_t pool;
	const char *path;
	const char *error;
	struct quota_root root;

	uint64_t storage_limit;
};

struct dirsize_quota_root_iter {
	struct quota_root_iter iter;

	int sent;
};

extern struct quota dirsize_quota;

static struct quota *dirsize_quota_init(const char *data)
{
	struct dirsize_quota *quota;
	const char *const *args;
	pool_t pool;

	pool = pool_alloconly_create("quota", 1024);
	quota = p_new(pool, struct dirsize_quota, 1);
	quota->pool = pool;
	quota->quota = dirsize_quota;

	args = t_strsplit(data, ":");
	quota->path = p_strdup(pool, args[0]);

	for (args++; *args != '\0'; args++) {
		if (strncmp(*args, "storage=", 8) == 0)
			quota->storage_limit = strtoull(*args + 8, NULL, 10);
	}

	if (getenv("DEBUG") != NULL) {
		i_info("dirsize quota path = %s", quota->path);
		i_info("dirsize quota limit = %llukB",
		       (unsigned long long)quota->storage_limit);
	}

	quota->root.quota = &quota->quota;
	return &quota->quota;
}

static void dirsize_quota_deinit(struct quota *_quota)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)_quota;

	pool_unref(quota->pool);
}

static struct quota_root_iter *
dirsize_quota_root_iter_init(struct quota *quota,
			     struct mailbox *box __attr_unused__)
{
	struct dirsize_quota_root_iter *iter;

	iter = i_new(struct dirsize_quota_root_iter, 1);
	iter->iter.quota = quota;
	return &iter->iter;
}

static struct quota_root *
dirsize_quota_root_iter_next(struct quota_root_iter *_iter)
{
	struct dirsize_quota_root_iter *iter =
		(struct dirsize_quota_root_iter *)_iter;
	struct dirsize_quota *quota = (struct dirsize_quota *)_iter->quota;

	if (iter->sent)
		return NULL;

	iter->sent = TRUE;
	return &quota->root;
}

static int dirsize_quota_root_iter_deinit(struct quota_root_iter *iter)
{
	i_free(iter);
	return 0;
}

static struct quota_root *
dirsize_quota_root_lookup(struct quota *_quota, const char *name)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)_quota;

	if (*name == '\0')
		return &quota->root;
	else
		return NULL;
}

static const char *
dirsize_quota_root_get_name(struct quota_root *root __attr_unused__)
{
	return "";
}

static const char *const *
dirsize_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static int
dirsize_quota_root_create(struct quota *_quota,
			  const char *name __attr_unused__,
			  struct quota_root **root_r __attr_unused__)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)_quota;

        quota->error = "Permission denied";
	return -1;
}

static int get_dir_usage(const char *dir, uint64_t *value)
{
	DIR *dirp;
	string_t *path;
	struct dirent *d;
	struct stat st;
	unsigned int path_pos;
        int ret;

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno == ENOENT)
			return 0;

		i_error("opendir(%s) failed: %m", dir);
		return -1;
	}

	path = t_str_new(128);
	str_append(path, dir);
	str_append_c(path, '/');
	path_pos = str_len(path);

	ret = 0;
	while ((d = readdir(dirp)) != NULL) {
		if (d->d_name[0] == '.' &&
		    (d->d_name[1] == '\0' ||
		     (d->d_name[1] == '.' && d->d_name[2] == '\0'))) {
			/* skip . and .. */
			continue;
		}

		str_truncate(path, path_pos);
		str_append(path, d->d_name);

		if (lstat(str_c(path), &st) < 0) {
			if (errno == ENOENT)
				continue;

			i_error("lstat(%s) failed: %m", dir);
			ret = -1;
			break;
		} else if (S_ISDIR(st.st_mode)) {
			if (get_dir_usage(str_c(path), value) < 0) {
				ret = -1;
				break;
			}
		} else {
			*value += st.st_size;
		}
	}

	(void)closedir(dirp);
	return ret;
}

static int
dirsize_quota_get_resource(struct quota_root *root, const char *name,
			   uint64_t *value_r, uint64_t *limit_r)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)root->quota;

	*value_r = 0;
	*limit_r = 0;

	if (strcasecmp(name, QUOTA_NAME_STORAGE) != 0)
		return 0;

	if (get_dir_usage(quota->path, value_r) < 0) {
		quota->error = "Internal quota calculation error";
		return -1;
	}
	*value_r /= 1024;
	*limit_r = quota->storage_limit;
	return 1;
}

static int
dirsize_quota_set_resource(struct quota_root *root,
			   const char *name __attr_unused__,
			   uint64_t value __attr_unused__)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)root->quota;

	quota->error = "Permission denied";
	return -1;
}

static struct quota_transaction_context *
dirsize_quota_transaction_begin(struct quota *_quota)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)_quota;
	struct quota_transaction_context *ctx;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = _quota;

	/* Get dir usage only once at the beginning of transaction.
	   When copying/appending lots of mails we don't want to re-read the
	   entire directory structure after each mail. */
	if (get_dir_usage(quota->path, &ctx->storage_current) < 0 ||
	    ctx->storage_current == (uoff_t)-1) {
                ctx->storage_current = (uoff_t)-1;
		quota->error = "Internal quota calculation error";
	}

	ctx->storage_limit = quota->storage_limit * 1024;
	return ctx;
}

static int
dirsize_quota_transaction_commit(struct quota_transaction_context *ctx)
{
	int ret = ctx->storage_current == (uoff_t)-1 ? -1 : 0;

	i_free(ctx);
	return ret;
}

static void
dirsize_quota_transaction_rollback(struct quota_transaction_context *ctx)
{
	i_free(ctx);
}

static int
dirsize_quota_try_alloc(struct quota_transaction_context *ctx,
			struct mail *mail, int *too_large_r)
{
	uoff_t size;

	if (ctx->storage_current == (uoff_t)-1)
		return -1;

	size = mail_get_physical_size(mail);
	*too_large_r = size > ctx->storage_limit;

	if (ctx->storage_current + ctx->bytes_diff + size > ctx->storage_limit)
		return 0;

	ctx->bytes_diff += size;
	return 1;
}

static void
dirsize_quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff += size;
}

static void
dirsize_quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff -= size;
}

static const char *dirsize_quota_last_error(struct quota *_quota)
{
	struct dirsize_quota *quota = (struct dirsize_quota *)_quota;

	return quota->error;
}

struct quota dirsize_quota = {
	"dirsize",

	dirsize_quota_init,
	dirsize_quota_deinit,

	dirsize_quota_root_iter_init,
	dirsize_quota_root_iter_next,
	dirsize_quota_root_iter_deinit,

	dirsize_quota_root_lookup,

	dirsize_quota_root_get_name,
	dirsize_quota_root_get_resources,

	dirsize_quota_root_create,
	dirsize_quota_get_resource,
	dirsize_quota_set_resource,

	dirsize_quota_transaction_begin,
	dirsize_quota_transaction_commit,
	dirsize_quota_transaction_rollback,

	dirsize_quota_try_alloc,
	dirsize_quota_alloc,
	dirsize_quota_free,

	dirsize_quota_last_error,

	ARRAY_INIT
};
