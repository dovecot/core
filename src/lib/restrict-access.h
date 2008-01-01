#ifndef RESTRICT_ACCESS_H
#define RESTRICT_ACCESS_H

/* set environment variables so they can be read with
   restrict_access_by_env() */
void restrict_access_set_env(ARRAY_TYPE(const_string) *env,
			     const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir,
			     gid_t first_valid_gid, gid_t last_valid_gid,
			     const char *extra_groups);

/* chroot, setuid() and setgid() based on environment variables.
   If disallow_roots is TRUE, we'll kill ourself if we didn't have the
   environment settings and we have root uid or gid. If env=NULL, the real
   environment is used. */
void restrict_access_by_env(ARRAY_TYPE(const_string) *env,
			    bool disallow_root);

#endif
