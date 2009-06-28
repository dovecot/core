#ifndef MKDIR_PARENTS_H
#define MKDIR_PARENTS_H

/* Create path and all the directories under it if needed. Permissions for
   existing directories isn't changed. Returns 0 if ok. If directory already
   exists, returns -1 with errno=EEXIST. */
int mkdir_parents(const char *path, mode_t mode);

/* Like mkdir_parents(), but use the given uid/gid for newly created
   directories. (uid_t)-1 or (gid_t)-1 can be used to indicate that it
   doesn't need to be changed. */
int mkdir_parents_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
/* Like mkdir_parents_chown(), but change only group. If chown() fails with
   EACCES, use gid_origin in the error message. */
int mkdir_parents_chgrp(const char *path, mode_t mode,
			gid_t gid, const char *gid_origin);

/* Like mkdir_parents_chown(), but don't actually create any parents. */
int mkdir_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_chgrp(const char *path, mode_t mode,
		gid_t gid, const char *gid_origin);

#endif
