/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

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

struct quota_count_path {
	const char *path;
	bool is_file;
};
ARRAY_DEFINE_TYPE(quota_count_path, struct quota_count_path);

extern struct quota_backend quota_backend_dirsize;

static struct quota_root *dirsize_quota_alloc(void)
{
	return i_new(struct quota_root, 1);
}

static void dirsize_quota_deinit(struct quota_root *_root)
{
	i_free(_root);
}

static const char *const *
dirsize_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE_KILOBYTES, NULL };

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

static int get_usage(const char *path, bool is_file, uint64_t *value_r)
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
		if (get_dir_usage(path, value_r) < 0)
			return -1;
	}
	return 0;
}

static void quota_count_path_add(ARRAY_TYPE(quota_count_path) *paths,
				 const char *path, bool is_file)
{
	struct quota_count_path *count_path;
	unsigned int i, count, path_len;

	path_len = strlen(path);
	count_path = array_get_modifiable(paths, &count);
	for (i = 0; i < count; ) {
		if (strncmp(count_path[i].path, path,
			    strlen(count_path[i].path)) == 0) {
			/* this path has already been counted */
			return;
		}
		if (strncmp(count_path[i].path, path, path_len) == 0 &&
		    count_path[i].path[path_len] == '/') {
			/* the new path contains the existing path.
			   drop it and see if there are more to drop. */
			array_delete(paths, i, 1);
			count_path = array_get_modifiable(paths, &count);
		} else {
			i++;
		}
	}

	count_path = array_append_space(paths);
	count_path->path = t_strdup(path);
	count_path->is_file = is_file;
}

static int
get_quota_root_usage(struct quota_root *root, uint64_t *value_r)
{
	struct mail_storage *const *storages;
	ARRAY_TYPE(quota_count_path) paths;
	const struct quota_count_path *count_paths;
	unsigned int i, count;
	const char *path;
	bool is_file;

	t_push();
	t_array_init(&paths, 8);
	storages = array_get(&root->quota->storages, &count);
	for (i = 0; i < count; i++) {
		path = mail_storage_get_mailbox_path(storages[i], "", &is_file);
		quota_count_path_add(&paths, path, is_file);

		/* INBOX may be in different path. */
		path = mail_storage_get_mailbox_path(storages[i], "INBOX",
						     &is_file);
		quota_count_path_add(&paths, path, is_file);
	}

	/* now sum up the found paths */
	*value_r = 0;
	count_paths = array_get(&paths, &count);
	for (i = 0; i < count; i++) {
		if (get_usage(count_paths[i].path, count_paths[i].is_file,
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
			   uint64_t *value_r, uint64_t *limit ATTR_UNUSED)
{
	if (strcasecmp(name, QUOTA_NAME_STORAGE_BYTES) != 0)
		return 0;

	if (get_quota_root_usage(_root, value_r) < 0)
		return -1;

	return 1;
}

static int 
dirsize_quota_update(struct quota_root *root ATTR_UNUSED, 
		     struct quota_transaction_context *ctx ATTR_UNUSED)
{
	return 0;
}

struct quota_backend quota_backend_dirsize = {
	"dirsize",

	{
		dirsize_quota_alloc,
		NULL,
		dirsize_quota_deinit,
		NULL,
		NULL,
		dirsize_quota_root_get_resources,
		dirsize_quota_get_resource,
		dirsize_quota_update
	}
};
