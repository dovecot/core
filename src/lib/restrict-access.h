#ifndef RESTRICT_ACCESS_H
#define RESTRICT_ACCESS_H

enum restrict_access_flags {
	/* If flags given to restrict_access() include
	 * RESTRICT_ACCESS_FLAG_ALLOW_ROOT, we won't kill
	 * ourself when we have root privileges. */
	RESTRICT_ACCESS_FLAG_ALLOW_ROOT = 1,
};

struct restrict_access_settings {
	/* UID to use, or (uid_t)-1 if you don't want to change it */
	uid_t uid;
	/* Effective GID to use, or (gid_t)-1 if you don't want to change it */
	gid_t gid;
	/* If not (gid_t)-1, the privileged GID can be temporarily
	   enabled/disabled. */
	gid_t privileged_gid;

	/* Add access to these space or comma -separated extra groups */
	const char *extra_groups;
	/* Add access to groups this system user belongs to */
	const char *system_groups_user;

	/* All specified GIDs must be in this range. If extra_groups or system
	   group user contains other GIDs, they're silently dropped. */
	gid_t first_valid_gid, last_valid_gid;

	/* Human readable "source" of UID and GID values. If non-NULL,
	   displayed on error messages about failing to change uid/gid. */
	const char *uid_source, *gid_source;

	/* Chroot directory */
	const char *chroot_dir;

	/* Allow running in setuid-root mode, where real UID is root and
	 * effective UID is non-root. By default the real UID is changed
	 * to be the same as the effective UID. */
	bool allow_setuid_root;
};

/* Initialize settings with values that don't change anything. */
void restrict_access_init(struct restrict_access_settings *set);
/* Restrict access as specified by the settings. If home is not NULL,
   it's chdir()ed after chrooting, otherwise it chdirs to / (the chroot). */
void restrict_access(const struct restrict_access_settings *set,
		     enum restrict_access_flags flags, const char *home)
		     ATTR_NULL(3);
/* Set environment variables so they can be read with
   restrict_access_by_env(). */
void restrict_access_set_env(const struct restrict_access_settings *set);
/* Read restrict_access_set_env() environments back into struct. */
void restrict_access_get_env(struct restrict_access_settings *set_r);
/* Read restrictions from environment and call restrict_access().
   If flags do not include RESTRICT_ACCESS_FLAG_ALLOW_ROOT, we'll kill ourself
   unless the RESTRICT_* environments caused root privileges to be dropped */
void restrict_access_by_env(enum restrict_access_flags flags,
			    const char *home) ATTR_NULL(2);

/* Return the chrooted directory if restrict_access*() chrooted,
   otherwise NULL. */
const char *restrict_access_get_current_chroot(void);

/*
   Checks if PR_SET_DUMPABLE environment variable is set, and if it is,
   calls restrict_access_set_dumpable(allow). 
*/
void restrict_access_allow_coredumps(bool allow);

/* Sets process dumpable true or false. Setting this true allows core dumping,
   reading /proc/self/io, attaching with PTRACE_ATTACH, and also changes
   ownership of /proc/[pid] directory. */
void restrict_access_set_dumpable(bool allow);

/* Gets process dumpability, returns TRUE if not supported, because
   we then assume that constraint is not present. */
bool restrict_access_get_dumpable(void);

/* If privileged_gid was set, these functions can be used to temporarily
   gain access to the group. */
int restrict_access_use_priv_gid(void);
void restrict_access_drop_priv_gid(void);
/* Returns TRUE if privileged GID exists for this process. */
bool restrict_access_have_priv_gid(void);

gid_t *restrict_get_groups_list(unsigned int *gid_count_r);

void restrict_access_deinit(void);

#endif
