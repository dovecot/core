/* Copyright (C) 2005-2006 Timo Sirainen */

/* Quota reporting based on simply summing sizes of all files in mailbox
   together. */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "quota-private.h"

#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

struct dirsize_quota_root {
	struct quota_root root;

	uint64_t storage_limit;
};

extern struct quota_backend quota_backend_dirsize;

static struct quota_root *
dirsize_quota_init(struct quota_setup *setup, const char *name)
{
	struct dirsize_quota_root *root;
	const char *const *args;

	root = i_new(struct dirsize_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_dirsize.v;

	t_push();
	args = t_strsplit(setup->data, ":");

	for (; *args != '\0'; args++) {
		if (strncmp(*args, "storage=", 8) == 0)
			root->storage_limit = strtoull(*args + 8, NULL, 10);
	}
	t_pop();

	if (getenv("DEBUG") != NULL) {
		i_info("dirsize quota limit = %llukB",
		       (unsigned long long)root->storage_limit);
	}

	return &root->root;
}

static void dirsize_quota_deinit(struct quota_root *_root)
{
	struct dirsize_quota_root *root = (struct dirsize_quota_root *)_root;

	i_free(root->root.name);
	i_free(root);
}

static bool
dirsize_quota_add_storage(struct quota_root *root __attr_unused__,
			  struct mail_storage *storage __attr_unused__)
{
	return TRUE;
}

static void
dirsize_quota_remove_storage(struct quota_root *root __attr_unused__,
			     struct mail_storage *storage __attr_unused__)
{
}

static const char *const *
dirsize_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
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
get_quota_root_usage(struct dirsize_quota_root *root, uint64_t *value_r)
{
	struct mail_storage *const *storages;
	unsigned int i, count;
	const char *path;
	bool is_file;

	storages = array_get(&root->root.storages, &count);
	for (i = 0; i < count; i++) {
		path = mail_storage_get_mailbox_path(storages[i], "", &is_file);

		if (get_dir_usage(path, value_r) < 0) {
			quota_set_error(root->root.setup->quota,
					"Internal quota calculation error");
			return -1;
		}
	}

	return 0;
}

static int
dirsize_quota_get_resource(struct quota_root *_root, const char *name,
			   uint64_t *value_r, uint64_t *limit_r)
{
	struct dirsize_quota_root *root = (struct dirsize_quota_root *)_root;

	*value_r = 0;
	*limit_r = 0;

	if (strcasecmp(name, QUOTA_NAME_STORAGE) != 0)
		return 0;

	if (get_quota_root_usage(root, value_r) < 0)
		return -1;

	*value_r /= 1024;
	*limit_r = root->storage_limit;
	return 1;
}

static int
dirsize_quota_set_resource(struct quota_root *root,
			   const char *name __attr_unused__,
			   uint64_t value __attr_unused__)
{
	quota_set_error(root->setup->quota, MAIL_STORAGE_ERR_NO_PERMISSION);
	return -1;
}

static struct quota_root_transaction_context *
dirsize_quota_transaction_begin(struct quota_root *_root,
				struct quota_transaction_context *_ctx)
{
	struct dirsize_quota_root *root = (struct dirsize_quota_root *)_root;
	struct quota_root_transaction_context *ctx;

	ctx = i_new(struct quota_root_transaction_context, 1);
	ctx->root = _root;
	ctx->ctx = _ctx;

	/* Get dir usage only once at the beginning of transaction.
	   When copying/appending lots of mails we don't want to re-read the
	   entire directory structure after each mail. */
	if (get_quota_root_usage(root, &ctx->bytes_current) < 0 ||
	    ctx->bytes_current == (uint64_t)-1) {
                ctx->bytes_current = (uint64_t)-1;
		quota_set_error(_root->setup->quota,
				"Internal quota calculation error");
	}

	ctx->bytes_limit = root->storage_limit * 1024;
	return ctx;
}

static int
dirsize_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	int ret = ctx->bytes_current == (uint64_t)-1 ? -1 : 0;

	i_free(ctx);
	return ret;
}

static void
dirsize_quota_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
}

static int
dirsize_quota_try_alloc_bytes(struct quota_root_transaction_context *ctx,
			      uoff_t size, bool *too_large_r)
{
	if (ctx->bytes_current == (uint64_t)-1)
		return -1;

	*too_large_r = size > ctx->bytes_limit;

	if (ctx->bytes_current + ctx->bytes_diff + size > ctx->bytes_limit)
		return 0;

	ctx->bytes_diff += size;
	return 1;
}

static int
dirsize_quota_try_alloc(struct quota_root_transaction_context *ctx,
			struct mail *mail, bool *too_large_r)
{
	uoff_t size;

	if (ctx->bytes_current == (uint64_t)-1)
		return -1;

	size = mail_get_physical_size(mail);
	if (size == (uoff_t)-1)
		return -1;

	return dirsize_quota_try_alloc_bytes(ctx, size, too_large_r);
}

static void
dirsize_quota_alloc(struct quota_root_transaction_context *ctx,
		    struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff += size;
}

static void
dirsize_quota_free(struct quota_root_transaction_context *ctx,
		   struct mail *mail)
{
	uoff_t size;

	size = mail_get_physical_size(mail);
	if (size != (uoff_t)-1)
		ctx->bytes_diff -= size;
}

struct quota_backend quota_backend_dirsize = {
	"dirsize",

	{
		dirsize_quota_init,
		dirsize_quota_deinit,

		dirsize_quota_add_storage,
		dirsize_quota_remove_storage,

		dirsize_quota_root_get_resources,

		dirsize_quota_get_resource,
		dirsize_quota_set_resource,

		dirsize_quota_transaction_begin,
		dirsize_quota_transaction_commit,
		dirsize_quota_transaction_rollback,

		dirsize_quota_try_alloc,
		dirsize_quota_try_alloc_bytes,
		dirsize_quota_alloc,
		dirsize_quota_free
	}
};
