#ifndef __RESTRICT_ACCESS_H
#define __RESTRICT_ACCESS_H

/* set environment variables so they can be read with
   restrict_access_by_env() */
void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir);

/* chroot, setuid() and setgid() based on environment variables */
void restrict_access_by_env(void);

#endif
