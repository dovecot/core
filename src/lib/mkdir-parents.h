#ifndef MKDIR_PARENTS_H
#define MKDIR_PARENTS_H

/* Create path and all the directories under it if needed.
   Returns 0 if ok, or if path already exists (not necessarily as directory). */
int mkdir_parents(const char *path, mode_t mode);

#endif
