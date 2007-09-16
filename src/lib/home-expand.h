#ifndef HOME_EXPAND_H
#define HOME_EXPAND_H

/* expand ~/ or ~user/ in beginning of path. If user is unknown, the original
   path is returned without modification. */
const char *home_expand(const char *path);
/* Returns 0 if ok, -1 if user wasn't found. */
int home_try_expand(const char **path);
/* Expand ~/ in the beginning of the path with the give home directory. */
const char *home_expand_tilde(const char *path, const char *home);

#endif
