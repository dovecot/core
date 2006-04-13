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

static int get_usage(struct dirsize_quota_root *root,
		     const char *path, bool is_file, uint64_t *value_r)
{
	struct stat st;

	if (is_file) {
		if (lstat(path, &st) < 0) {
			if (errno == ENOENT)
				return 0;

			i_error("lstat(%s) failed: %m", path);
			return -1;
		}
		*value_r += st.st_size;
	} else {
		if (get_dir_usage(path, value_r) < 0) {
			quota_set_error(root->root.setup->quota,
					"Internal quota calculation error");
			return -1;
		}
	}
	return 0;
}

struct quota_count_path {
	const char *path;
	bool is_file;
};

static void quota_count_path_add(array_t *paths, const char *path, bool is_file)
{
	ARRAY_SET_TYPE(paths, struct quota_count_path);
	struct quota_count_path *count_path;
	unsigned int i, count;

	count_path = array_get_modifyable(paths, &count);
	for (i = 0; i < count; i++) {
		if (strncmp(count_path[i].path, path,
			    strlen(count_path[i].path)) == 0) {
			/* this path is already being counted */
			return;
		}
		if (strncmp(count_path[i].path, path, strlen(path)) == 0) {
			/* the new path contains the existing path */
			i_assert(!is_file);
			count_path += i;
			break;
		}
	}

	if (i == count)
		count_path = array_append_space(paths);
	count_path->path = t_strdup(path);
	count_path->is_file = is_file;
}

static int
get_quota_root_usage(struct dirsize_quota_root *root, uint64_t *value_r)
{
	struct mail_storage *const *storages;
	array_t ARRAY_DEFINE(paths, struct quota_count_path);
	const struct quota_count_path *count_paths;
	unsigned int i, count;
	const char *path;
	bool is_file;

	t_push();
	ARRAY_CREATE(&paths, pool_datastack_create(),
		     struct quota_count_path, 8);
	storages = array_get(&root->root.storages, &count);
	for (i = 0; i < count; i++) {
		path = mail_storage_get_mailbox_path(storages[i], "", &is_file);
		quota_count_path_add(&paths, path, is_file);

		/* INBOX may be in different path. */
		path = mail_storage_get_mailbox_path(storages[i], "INBOX",
						     &is_file);
		quota_count_path_add(&paths, path, is_file);
	}

	/* now sum up the found paths */
	count_paths = array_get(&paths, &count);
	for (i = 0; i < count; i++) {
		if (get_usage(root, count_paths[i].path, count_paths[i].is_file,
			      value_r) < 0) {
			t_pop();
			return -1;
		}
	}

	t_pop();

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
	ctx->count_limit = (uint64_t)-1;
	return ctx;
}

static int
dirsize_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	int ret = ctx->bytes_current == (uint64_t)-1 ? -1 : 0;

	i_free(ctx);
	return ret;
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
		quota_default_transaction_rollback,

		quota_default_try_alloc,
		quota_default_try_alloc_bytes,
		quota_default_alloc,
		quota_default_free
	}
};
