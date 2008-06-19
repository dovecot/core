/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#define _GNU_SOURCE /* setresgid() */
#include <sys/types.h>
#include <unistd.h>

#include "lib.h"
#include "restrict-access.h"
#include "env-util.h"

#include <stdio.h> /* for AIX */
#include <stdlib.h>
#include <time.h>
#include <grp.h>

static gid_t process_primary_gid = (gid_t)-1;
static gid_t process_privileged_gid = (gid_t)-1;
static bool process_using_priv_gid = FALSE;

void restrict_access_set_env(const char *user, uid_t uid,
			     gid_t gid, gid_t privileged_gid,
			     const char *chroot_dir,
			     gid_t first_valid_gid, gid_t last_valid_gid,
			     const char *extra_groups)
{
	if (user != NULL && *user != '\0')
		env_put(t_strconcat("RESTRICT_USER=", user, NULL));
	if (chroot_dir != NULL && *chroot_dir != '\0')
		env_put(t_strconcat("RESTRICT_CHROOT=", chroot_dir, NULL));

	env_put(t_strdup_printf("RESTRICT_SETUID=%s", dec2str(uid)));
	env_put(t_strdup_printf("RESTRICT_SETGID=%s", dec2str(gid)));
	if (privileged_gid != (gid_t)-1) {
		env_put(t_strdup_printf("RESTRICT_SETGID_PRIV=%s",
					dec2str(privileged_gid)));
	}
	if (extra_groups != NULL && *extra_groups != '\0') {
		env_put(t_strconcat("RESTRICT_SETEXTRAGROUPS=",
				    extra_groups, NULL));
	}

	if (first_valid_gid != 0) {
		env_put(t_strdup_printf("RESTRICT_GID_FIRST=%s",
					dec2str(first_valid_gid)));
	}
	if (last_valid_gid != 0) {
		env_put(t_strdup_printf("RESTRICT_GID_LAST=%s",
					dec2str(last_valid_gid)));
	}
}

static void restrict_init_groups(gid_t primary_gid, gid_t privileged_gid)
{
	if (privileged_gid == (gid_t)-1) {
		if (primary_gid == getgid() && primary_gid == getegid()) {
			/* everything is already set */
			return;
		}

		if (setgid(primary_gid) != 0) {
			i_fatal("setgid(%s) failed with euid=%s, "
				"gid=%s, egid=%s: %m",
				dec2str(primary_gid), dec2str(geteuid()),
				dec2str(getgid()), dec2str(getegid()));
		}
		return;
	}

	if (getegid() != 0 && primary_gid == getgid() &&
	    primary_gid == getegid()) {
		/* privileged_gid is hopefully in saved ID. if not,
		   there's nothing we can do about it. */
		return;
	}

#ifdef HAVE_SETRESGID
	if (setresgid(primary_gid, primary_gid, privileged_gid) != 0) {
		i_fatal("setresgid(%s,%s,%s) failed with euid=%s: %m",
			dec2str(primary_gid), dec2str(primary_gid),
			dec2str(privileged_gid), dec2str(geteuid()));
	}
#else
	if (geteuid() == 0) {
		/* real, effective, saved -> privileged_gid */
		if (setgid(privileged_gid) < 0) {
			i_fatal("setgid(%s) failed: %m",
				dec2str(privileged_gid));
		}
	}
	/* real, effective -> primary_gid
	   saved -> keep */
	if (setregid(primary_gid, primary_gid) != 0) {
		i_fatal("setregid(%s,%s) failed with euid=%s: %m",
			dec2str(primary_gid), dec2str(privileged_gid),
			dec2str(geteuid()));
	}
#endif
}

static gid_t *get_groups_list(unsigned int *gid_count_r)
{
	gid_t *gid_list;
	int ret, gid_count;

	if ((gid_count = getgroups(0, NULL)) < 0)
		i_fatal("getgroups() failed: %m");

	/* @UNSAFE */
	gid_list = t_new(gid_t, gid_count);
	if ((ret = getgroups(gid_count, gid_list)) < 0)
		i_fatal("getgroups() failed: %m");

	*gid_count_r = ret;
	return gid_list;
}

static void drop_restricted_groups(gid_t *gid_list, unsigned int *gid_count,
				   bool *have_root_group)
{
	/* @UNSAFE */
	gid_t first_valid, last_valid;
	const char *env;
	unsigned int i, used;

	env = getenv("RESTRICT_GID_FIRST");
	first_valid = env == NULL ? 0 : (gid_t)strtoul(env, NULL, 10);
	env = getenv("RESTRICT_GID_LAST");
	last_valid = env == NULL ? (gid_t)-1 : (gid_t)strtoul(env, NULL, 10);

	for (i = 0, used = 0; i < *gid_count; i++) {
		if (gid_list[i] >= first_valid &&
		    (last_valid == (gid_t)-1 || gid_list[i] <= last_valid)) {
			if (gid_list[i] == 0)
				*have_root_group = TRUE;
			gid_list[used++] = gid_list[i];
		}
	}
	*gid_count = used;
}

static gid_t get_group_id(const char *name)
{
	struct group *group;

	if (is_numeric(name, '\0'))
		return (gid_t)strtoul(name, NULL, 10);

	group = getgrnam(name);
	if (group == NULL)
		i_fatal("unknown group name in extra_groups: %s", name);
	return group->gr_gid;
}

static void fix_groups_list(const char *extra_groups,
			    bool preserve_existing, bool *have_root_group)
{
	gid_t gid, *gid_list, *gid_list2;
	const char *const *tmp, *empty = NULL;
	unsigned int i, gid_count;
	bool add_primary_gid;

	/* if we're using a privileged GID, we can temporarily drop our
	   effective GID. we still want to be able to use its privileges,
	   so add it to supplementary groups. */
	add_primary_gid = process_privileged_gid != (gid_t)-1;

	tmp = extra_groups == NULL ? &empty :
		t_strsplit_spaces(extra_groups, ", ");

	if (preserve_existing) {
		gid_list = get_groups_list(&gid_count);
		drop_restricted_groups(gid_list, &gid_count,
				       have_root_group);
		/* see if the list already contains the primary GID */
		for (i = 0; i < gid_count; i++) {
			if (gid_list[i] == process_primary_gid) {
				add_primary_gid = FALSE;
				break;
			}
		}
	} else {
		gid_list = NULL;
		gid_count = 0;
	}
	if (gid_count == 0) {
		/* Some OSes don't like an empty groups list,
		   so use the primary GID as the only one. */
		gid_list = t_new(gid_t, 2);
		gid_list[0] = process_primary_gid;
		gid_count = 1;
		add_primary_gid = FALSE;
	}

	if (*tmp != NULL || add_primary_gid) {
		/* @UNSAFE: add extra groups and/or primary GID to gids list */
		gid_list2 = t_new(gid_t, gid_count + str_array_length(tmp) + 1);
		memcpy(gid_list2, gid_list, gid_count * sizeof(gid_t));
		for (; *tmp != NULL; tmp++) {
			gid = get_group_id(*tmp);
			if (gid != process_primary_gid)
				gid_list2[gid_count++] = gid;
		}
		if (add_primary_gid)
			gid_list2[gid_count++] = process_primary_gid;
		gid_list = gid_list2;
	}

	if (setgroups(gid_count, gid_list) < 0) {
		if (errno == EINVAL) {
			i_fatal("setgroups(%s) failed: Too many extra groups",
				extra_groups == NULL ? "" : extra_groups);
		} else {
			i_fatal("setgroups() failed: %m");
		}
	}
}

void restrict_access_by_env(bool disallow_root)
{
	const char *env;
	uid_t uid;
	bool is_root, have_root_group, preserve_groups = FALSE;
	bool allow_root_gid;

	is_root = geteuid() == 0;

	/* set the primary/privileged group */
	env = getenv("RESTRICT_SETGID");
	process_primary_gid = env == NULL || *env == '\0' ? (gid_t)-1 :
		(gid_t)strtoul(env, NULL, 10);
	env = getenv("RESTRICT_SETGID_PRIV");
	process_privileged_gid = env == NULL || *env == '\0' ? (gid_t)-1 :
		(gid_t)strtoul(env, NULL, 10);

	have_root_group = process_primary_gid == 0;
	if (process_primary_gid != (gid_t)-1 ||
	    process_privileged_gid != (gid_t)-1) {
		if (process_primary_gid == (gid_t)-1)
			process_primary_gid = getegid();
		restrict_init_groups(process_primary_gid,
				     process_privileged_gid);
	} else {
		if (process_primary_gid == (gid_t)-1)
			process_primary_gid = getegid();
	}

	/* set system user's groups */
	env = getenv("RESTRICT_USER");
	if (env != NULL && *env != '\0' && is_root) {
		if (initgroups(env, process_primary_gid) < 0) {
			i_fatal("initgroups(%s, %s) failed: %m",
				env, dec2str(process_primary_gid));
		}
		preserve_groups = TRUE;
	}

	/* add extra groups. if we set system user's groups, drop the
	   restricted groups at the same time. */
	env = getenv("RESTRICT_SETEXTRAGROUPS");
	if (is_root) T_BEGIN {
		fix_groups_list(env, preserve_groups, &have_root_group);
	} T_END;

	/* chrooting */
	env = getenv("RESTRICT_CHROOT");
	if (env != NULL && *env != '\0') {
		/* kludge: localtime() must be called before chroot(),
		   or the timezone isn't known */
		const char *home = getenv("HOME");
		time_t t = 0;
		(void)localtime(&t);

		if (chroot(env) != 0)
			i_fatal("chroot(%s) failed: %m", env);

		if (home != NULL) {
			if (chdir(home) < 0) {
				i_error("chdir(%s) failed: %m", home);
				home = NULL;
			}
		}
		if (home == NULL) {
			if (chdir("/") != 0)
				i_fatal("chdir(/) failed: %m");
		}
	}

	/* uid last */
	env = getenv("RESTRICT_SETUID");
	uid = env == NULL || *env == '\0' ? 0 : (uid_t)strtoul(env, NULL, 10);
	if (uid != 0) {
		if (setuid(uid) != 0) {
			i_fatal("setuid(%s) failed with euid=%s: %m",
				dec2str(uid), dec2str(geteuid()));
		}
	}

	/* verify that we actually dropped the privileges */
	if (uid != 0 || disallow_root) {
		if (setuid(0) == 0) {
			if (uid == 0)
				i_fatal("Running as root isn't permitted");
			i_fatal("We couldn't drop root privileges");
		}
	}

	env = getenv("RESTRICT_GID_FIRST");
	if (env != NULL && atoi(env) != 0)
		allow_root_gid = FALSE;
	else if (process_primary_gid == 0 || process_privileged_gid == 0)
		allow_root_gid = TRUE;
	else
		allow_root_gid = FALSE;

	if (!allow_root_gid && uid != 0) {
		if (getgid() == 0 || getegid() == 0 || setgid(0) == 0) {
			if (process_primary_gid == 0)
				i_fatal("GID 0 isn't permitted");
			i_fatal("We couldn't drop root group privileges "
				"(wanted=%s, gid=%s, egid=%s)",
				dec2str(process_primary_gid),
				dec2str(getgid()), dec2str(getegid()));
		}
	}

	/* clear the environment, so we don't fail if we get back here */
	env_put("RESTRICT_USER=");
	env_put("RESTRICT_CHROOT=");
	env_put("RESTRICT_SETUID=");
	if (process_privileged_gid == (gid_t)-1) {
		/* if we're dropping privileges before executing and
		   a privileged group is set, the groups must be fixed
		   after exec */
		env_put("RESTRICT_SETGID=");
		env_put("RESTRICT_SETGID_PRIV=");
	}
	env_put("RESTRICT_SETEXTRAGROUPS=");
	env_put("RESTRICT_GID_FIRST=");
	env_put("RESTRICT_GID_LAST=");
}

int restrict_access_use_priv_gid(void)
{
	i_assert(!process_using_priv_gid);

	if (process_privileged_gid == (gid_t)-1)
		return 0;
	if (setegid(process_privileged_gid) < 0) {
		i_error("setegid(privileged) failed: %m");
		return -1;
	}
	process_using_priv_gid = TRUE;
	return 0;
}

void restrict_access_drop_priv_gid(void)
{
	if (!process_using_priv_gid)
		return;

	if (setegid(process_primary_gid) < 0)
		i_fatal("setegid(primary) failed: %m");
	process_using_priv_gid = FALSE;
}

bool restrict_access_have_priv_gid(void)
{
	return process_privileged_gid != (gid_t)-1;
}
