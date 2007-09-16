#ifndef SAFE_MKDIR_H
#define SAFE_MKDIR_H

/* Either create a directory or make sure that it already exists with given
   permissions. If anything fails, the i_fatal() is called. Returns 1 if
   directory was created, 2 if it already existed with correct permissions,
   0 if we changed permissions. */
int safe_mkdir(const char *dir, mode_t mode, uid_t uid, gid_t gid);

#endif
