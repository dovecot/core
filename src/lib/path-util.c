/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "path-util.h"

#include <unistd.h>

const char *t_abspath(const char *path)
{
	i_assert(path != NULL);

	if (*path == '/')
		return path;

	const char *dir, *error;
	if (t_get_working_dir(&dir, &error) < 0)
		i_fatal("Failed to get working directory: %s", error);
	return t_strconcat(dir, "/", path, NULL);
}

const char *t_abspath_to(const char *path, const char *root)
{
	i_assert(path != NULL);
	i_assert(root != NULL);

	if (*path == '/')
		return path;

	return t_strconcat(root, "/", path, NULL);
}

int t_get_working_dir(const char **dir_r, const char **error_r)
{
	i_assert(error_r != NULL);

	/* @UNSAFE */
	char *dir;
	size_t size = 128;

	dir = t_buffer_get(size);
	while (getcwd(dir, size) == NULL) {
		if (errno != ERANGE) {
			*error_r = t_strdup_printf("getcwd() failed: %m");
			return -1;
		}
		size = nearest_power(size+1);
		dir = t_buffer_get(size);
	}
	t_buffer_alloc(strlen(dir) + 1);
	*dir_r = dir;
	return 0;
}

int t_readlink(const char *path, const char **dest_r, const char **error_r)
{
	i_assert(error_r != NULL);

	/* @UNSAFE */
	ssize_t ret;
	char *dest;
	size_t size = 128;

	dest = t_buffer_get(size);
	while ((ret = readlink(path, dest, size)) >= (ssize_t)size) {
		size = nearest_power(size+1);
		dest = t_buffer_get(size);
	}
	if (ret < 0) {
		*error_r = t_strdup_printf("readlink() failed: %m");
		return -1;
	}

	dest[ret] = '\0';
	t_buffer_alloc(ret + 1);
	*dest_r = dest;
	return 0;
}

bool t_binary_abspath(const char **binpath)
{
	const char *path_env, *const *paths;
	string_t *path;

	if (**binpath == '/') {
		/* already have absolute path */
		return TRUE;
	} else if (strchr(*binpath, '/') != NULL) {
		/* relative to current directory */
		*binpath = t_abspath(*binpath);
		return TRUE;
	} else if ((path_env = getenv("PATH")) != NULL) {
		/* we have to find our executable from path */
		path = t_str_new(256);
		paths = t_strsplit(path_env, ":");
		for (; *paths != NULL; paths++) {
			str_append(path, *paths);
			str_append_c(path, '/');
			str_append(path, *binpath);
			if (access(str_c(path), X_OK) == 0) {
				*binpath = str_c(path);
				return TRUE;
			}
			str_truncate(path, 0);
		}
	}
	return FALSE;
}
