#ifndef __RESTRICT_ACCESS_H
#define __RESTRICT_ACCESS_H

/* set environment variables so they can be read with
   restrict_access_by_env() */
void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir);

/* clear the environment variables set by restrict_access_set_env() */
void restrict_access_clear_env(void);

/* chroot, setuid() and setgid() based on environment variables.
   If disallow_roots is TRUE, we'll kill ourself if we didn't have the
   environment settings and we have root uid or gid. */
void restrict_access_by_env(int disallow_root);

#endif
