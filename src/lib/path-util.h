#ifndef PATH_UTIL_H
#define PATH_UTIL_H

/* Returns path as the normalized absolute path, which means that './'
 * and '../' components are resolved, and that duplicate and trailing
 * slashes are removed. If it's not already the absolute path, it's
 * assumed to be relative to the current working directory.
 *
 * NOTE: Be careful with this function. The resolution of '../' components
 * with the parent component as if it were a normal directory is not valid
 * if the path contains symbolic links.
 *
 * Returns 0 on success, and -1 on failure. errno and error_r are set on
 * failure, and error_r cannot be NULL.
 */
int t_normpath(const char *path, const char **npath_r, const char **error_r);
/* Like t_normpath(), but path is relative to given root. */
int t_normpath_to(const char *path, const char *root, const char **npath_r,
		  const char **error_r);

/* Returns path as the real normalized absolute path, which means that all
 * symbolic links in the path are resolved, that './' and '../' components
 * are resolved, and that duplicate and trailing slashes are removed. If it's
 * not already the absolute path, it's assumed to be relative to the current
 * working directory.
 *
 * NOTE: This function calls stat() for each path component and more when
 * there are symbolic links (just like POSIX realpath()).
 *
 * Returns 0 on success, and -1 on failure. errno and error_r are set on
 * failure, and error_r cannot be NULL.
 */
int t_realpath(const char *path, const char **npath_r, const char **error_r);
/* Like t_realpath(), but path is relative to given root. */
int t_realpath_to(const char *path, const char *root, const char **npath_r,
		  const char **error_r);

/* Returns path as absolute path. If it's not already absolute path,
 * it's assumed to be relative to current working directory.
 *
 * In the t_abspath functions, the returned paths are not normalized. This
 * means that './' and '../' are not resolved, but they left in the returned
 * path as given in the parameters. Symbolic links are not resolved either.
 *
 * Returns 0 on success, and -1 on failure. error_r is set on failure, and
 * cannot be NULL.
 */
int t_abspath(const char *path, const char **abspath_r, const char **error_r);
/* Like t_abspath(), but path is relative to given root. */
const char *t_abspath_to(const char *path, const char *root);

/* Get current working directory allocated from data stack. Returns 0 on
 * success and 1 on failure. error_r is set on failure and cannot be NULL. */
int t_get_working_dir(const char **dir_r, const char **error_r);

/* Get symlink destination allocated from data stack. Returns 0 on success and
 * -1 on failure. error_r is set on failure and cannot be NULL. */
int t_readlink(const char *path, const char **dest_r, const char **error_r);

/* Update binpath to be absolute:
   a) begins with '/' -> no change
   b) contains '/' -> assume relative to working directory
   c) set to first executable that's found from $PATH

   If no usable binary was found, return FALSE. */
bool t_binary_abspath(const char **binpath);

#endif
