/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "path-util.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PATH_UTIL_MAX_PATH      8*1024
#define PATH_UTIL_MAX_SYMLINKS  80

static int t_getcwd_alloc(char **dir_r, size_t *asize_r,
			  const char **error_r) ATTR_NULL(2)
{
	/* @UNSAFE */
	char *dir;
	size_t asize = 128;

	dir = t_buffer_get(asize);
	while (getcwd(dir, asize) == NULL) {
		if (errno != ERANGE) {
			*error_r = t_strdup_printf("getcwd() failed: %m");
			return -1;
		}
		asize = nearest_power(asize+1);
		dir = t_buffer_get(asize);
	}
	if (asize_r != NULL)
		*asize_r = asize;
	*dir_r = dir;
	return 0;
}

static int path_normalize(const char *path, bool resolve_links,
			  const char **npath_r, const char **error_r)
{
	/* @UNSAFE */
	unsigned int link_count = 0;
	char *npath, *npath_pos;
	const char *p;
	size_t asize;

	i_assert(path != NULL);
	i_assert(npath_r != NULL);
	i_assert(error_r != NULL);

	if (path[0] != '/') {
		/* relative; initialize npath with current directory */
		if (t_getcwd_alloc(&npath, &asize, error_r) < 0)
			return -1;
		npath_pos = npath + strlen(npath);
		i_assert(npath[0] == '/');
	} else {
		/* absolute; initialize npath with root */
		asize = 128;
		npath = t_buffer_get(asize);
		npath[0] = '/';
		npath_pos = npath + 1;
	}

	p = path;
	while (*p != '\0') {
		struct stat st;
		ptrdiff_t seglen;
		const char *segend;

		/* skip duplicate shashes */
		while (*p == '/')
			p++;

		/* find end of path segment */
		for (segend = p; *segend != '\0' && *segend != '/'; segend++);

		if (segend == p)
			break; /* '\0' */
		seglen = segend - p;
		if (seglen == 1 && p[0] == '.') {
			/* a reference to this segment; nothing to do */
		} else if (seglen == 2 && p[0] == '.' && p[1] == '.') {
			/* a reference to parent segment; back up to previous
			 * slash */
			if (npath_pos > npath + 1) {
				if (*(npath_pos-1) == '/')
					npath_pos--;
				for (; *(npath_pos-1) != '/'; npath_pos--);
			}
		} else {
			/* make sure npath now ends in slash */
			if (*(npath_pos-1) != '/') {
				i_assert(npath_pos + 1 < npath + asize);
				*(npath_pos++) = '/';
			}

			/* allocate space if necessary */
			if ((npath_pos + seglen + 1) >= (npath + asize)) {
				ptrdiff_t npath_offset = npath_pos - npath;
				asize = nearest_power(npath_offset + seglen + 2);
				npath = t_buffer_reget(npath, asize);
				npath_pos = npath + npath_offset;
			}

			/* copy segment to normalized path */
			i_assert(p + seglen < npath + asize);
			(void)memmove(npath_pos, p, seglen);
			npath_pos += seglen;
		}

		if (resolve_links) {
			/* stat path up to here (segend points to tail) */
			*npath_pos = '\0';
			if (lstat(npath, &st) < 0) {
				*error_r = t_strdup_printf("lstat() failed: %m");
				return -1;
			}

			if (S_ISLNK (st.st_mode)) {
				/* symlink */
				char *npath_link;
				size_t lsize = 128, tlen = strlen(segend), espace;
				size_t ltlen = (link_count == 0 ? 0 : tlen);
				ssize_t ret;

				/* limit link dereferences */
				if (++link_count > PATH_UTIL_MAX_SYMLINKS) {
					errno = ELOOP;
					*error_r = "Too many symlink dereferences";
					return -1;
				}

				/* allocate space for preserving tail of previous symlink and
				   first attempt at reading symlink with room for the tail

				   buffer will look like this:
				   [npath][0][preserved tail][link buffer][room for tail][0]
				 */
				espace = ltlen + tlen + 2;
				if ((npath_pos + espace + lsize) >= (npath + asize)) {
					ptrdiff_t npath_offset = npath_pos - npath;
					asize = nearest_power((npath_offset + espace + lsize) + 1);
					lsize = asize - (npath_offset + espace);
					npath = t_buffer_reget(npath, asize);
					npath_pos = npath + npath_offset;
				}

				if (ltlen > 0) {
					/* preserve tail just after end of npath */
					(void)memmove(npath_pos + 1, segend, ltlen);
				}

				/* read the symlink after the preserved tail */
				for (;;) {
					npath_link = (npath_pos + 1) + ltlen;

					i_assert(npath_link + lsize < npath + asize);

					/* attempt to read the link */
					if ((ret=readlink(npath, npath_link, lsize)) < 0) {
						*error_r = t_strdup_printf("readlink() failed: %m");
						return -1;
					}
					if ((size_t)ret < lsize) {
						/* make static analyzers happy */
						npath_link[ret] = '\0';
						break;
					}

					/* sum of new symlink content length
					 * and path tail length may not
					   exceed maximum */
					if ((size_t)(ret + tlen) >= PATH_UTIL_MAX_PATH) {
						errno = ENAMETOOLONG;
						*error_r = "Resulting path is too long";
						return -1;
					}

					/* try again with bigger buffer */
					espace = ltlen + tlen + 2;
					if ((npath_pos + espace + lsize) >= (npath + asize)) {
						ptrdiff_t npath_offset = npath_pos - npath;
						asize = nearest_power((npath_offset + espace + lsize) + 1);
						lsize = asize - (npath_offset + espace);
						npath = t_buffer_reget(npath, asize);
						npath_pos = npath + npath_offset;
					}
				}

				/* add tail of previous path at end of symlink */
				if (ltlen > 0) {
					i_assert(npath_pos + 1 + tlen < npath + asize);
					(void)memcpy(npath_link + ret, npath_pos + 1, tlen);
				} else {
					i_assert(segend + tlen < npath + asize);
					(void)memcpy(npath_link + ret, segend, tlen);
				}
				*(npath_link+ret+tlen) = '\0';

				/* use as new source path */
				path = segend = npath_link;

				if (path[0] == '/') {
					/* absolute symlink; start over at root */
					npath_pos = npath + 1;
				} else {
					/* relative symlink; back up to previous segment */
					if (npath_pos > npath + 1) {
						if (*(npath_pos-1) == '/')
							npath_pos--;
						for (; *(npath_pos-1) != '/'; npath_pos--);
					}
				}

			} else if (*segend != '\0' && !S_ISDIR (st.st_mode)) {
				/* not last segment, but not a directory either */
				errno = ENOTDIR;
				*error_r = t_strdup_printf("Not a directory: %s", npath);
				return -1;
			}
		}

		p = segend;
	}

	i_assert(npath_pos < npath + asize);

	/* remove any trailing slash */
	if (npath_pos > npath + 1 && *(npath_pos-1) == '/')
		npath_pos--;
	*npath_pos = '\0';

	t_buffer_alloc(npath_pos - npath + 1);
	*npath_r = npath;
	return 0;
}

int t_normpath(const char *path, const char **npath_r, const char **error_r)
{
	return path_normalize(path, FALSE, npath_r, error_r);
}

int t_normpath_to(const char *path, const char *root, const char **npath_r,
		  const char **error_r)
{
	i_assert(path != NULL);
	i_assert(root != NULL);
	i_assert(npath_r != NULL);

	if (*path == '/')
		return t_normpath(path, npath_r, error_r);

	return t_normpath(t_strconcat(root, "/", path, NULL), npath_r, error_r);
}

int t_realpath(const char *path, const char **npath_r, const char **error_r)
{
	return path_normalize(path, TRUE, npath_r, error_r);
}

int t_realpath_to(const char *path, const char *root, const char **npath_r,
		  const char **error_r)
{
	i_assert(path != NULL);
	i_assert(root != NULL);
	i_assert(npath_r != NULL);

	if (*path == '/')
		return t_realpath(path, npath_r, error_r);

	return t_realpath(t_strconcat(root, "/", path, NULL), npath_r, error_r);
}

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
	i_assert(dir_r != NULL);
	i_assert(error_r != NULL);
	return t_getcwd_alloc((char**)dir_r, NULL, error_r);
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
