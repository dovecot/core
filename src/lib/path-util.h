#ifndef PATH_UTIL_H
#define PATH_UTIL_H

/* Returns path as absolute path. If it's not already absolute path,
 * it's assumed to be relative to current working directory.
 *
 * In the t_abspath functions, the returned paths are not normalized. This
 * means that './' and '../' are not resolved, but they left in the returned
 * path as given in the parameters. Symbolic links are not resolved either.
 */
const char *t_abspath(const char *path);
/* Like t_abspath(), but path is relative to given root. */
const char *t_abspath_to(const char *path, const char *root);

/* Returns current directory, allocated from data stack. */
int t_get_current_dir(const char **dir_r);

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
