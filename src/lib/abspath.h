#ifndef ABSPATH_H
#define ABSPATH_H

/* Returns path as absolute path. If it's not already absolute path,
   it's assumed to be relative to current working directory. */
const char *t_abspath(const char *path);
/* Like t_abspath(), but path is relative to given root. */
const char *t_abspath_to(const char *path, const char *root);

#endif
