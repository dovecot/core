#ifndef RESTRICT_ACCESS_H
#define RESTRICT_ACCESS_H

/* set environment variables so they can be read with
   restrict_access_by_env(). If privileged_gid != (gid_t)-1,
   the privileged GID can be temporarily enabled/disabled. */
void restrict_access_set_env(const char *user, uid_t uid,
			     gid_t gid, gid_t privileged_gid,
			     const char *chroot_dir,
			     gid_t first_valid_gid, gid_t last_valid_gid,
			     const char *extra_groups);

/* chroot, setuid() and setgid() based on environment variables.
   If disallow_roots is TRUE, we'll kill ourself if we didn't have the
   environment settings and we have root uid or gid. */
void restrict_access_by_env(bool disallow_root);

/* Try to set up the process in a way that core dumps are still allowed
   after calling restrict_access_by_env(). */
void restrict_access_allow_coredumps(bool allow);

/* If privileged_gid was set, these functions can be used to temporarily
   gain access to the group. */
int restrict_access_use_priv_gid(void);
void restrict_access_drop_priv_gid(void);
/* Returns TRUE if privileged GID exists for this process. */
bool restrict_access_have_priv_gid(void);

#endif
