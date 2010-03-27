#ifndef ABSPATH_H
#define ABSPATH_H

/* Returns path as absolute path. If it's not already absolute path,
   it's assumed to be relative to current working directory. */
const char *t_abspath(const char *path);
/* Like t_abspath(), but path is relative to given root. */
const char *t_abspath_to(const char *path, const char *root);

/* Returns current directory, allocated from data stack. */
int t_get_current_dir(const char **dir_r);
/* Returns symlink destination, allocated from data stack. */
int t_readlink(const char *path, const char **dest_r);

/* Update binpath to be absolute:
   a) begins with '/' -> no change
   b) contains '/' -> assume relative to working directory
   c) set to first executable that's found from $PATH

   If no usable binary was found, return FALSE. */
bool t_binary_abspath(const char **binpath);

#endif
