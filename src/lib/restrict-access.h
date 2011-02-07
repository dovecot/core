#ifndef RESTRICT_ACCESS_H
#define RESTRICT_ACCESS_H

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
};

/* Initialize settings with values that don't change anything. */
void restrict_access_init(struct restrict_access_settings *set);
/* Restrict access as specified by the settings. If home is not NULL,
   it's chdir()ed after chrooting, otherwise it chdirs to / (the chroot). */
void restrict_access(const struct restrict_access_settings *set,
		     const char *home, bool disallow_root);
/* Set environment variables so they can be read with
   restrict_access_by_env(). */
void restrict_access_set_env(const struct restrict_access_settings *set);
/* Read restrict_access_set_env() environments back into struct. */
void restrict_access_get_env(struct restrict_access_settings *set_r);
/* Read restrictions from environment and call restrict_access().
   If disallow_roots is TRUE, we'll kill ourself if we didn't have the
   environment settings. */
void restrict_access_by_env(const char *home, bool disallow_root);

/* Return the chrooted directory if restrict_access*() chrooted,
   otherwise NULL. */
const char *restrict_access_get_current_chroot(void);

/* Try to set up the process in a way that core dumps are still allowed
   after calling restrict_access_by_env(). */
void restrict_access_allow_coredumps(bool allow);

/* If privileged_gid was set, these functions can be used to temporarily
   gain access to the group. */
int restrict_access_use_priv_gid(void);
void restrict_access_drop_priv_gid(void);
/* Returns TRUE if privileged GID exists for this process. */
bool restrict_access_have_priv_gid(void);

gid_t *restrict_get_groups_list(unsigned int *gid_count_r);

#endif
