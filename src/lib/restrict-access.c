/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "restrict-access.h"
#include "env-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <grp.h>

enum restrict_env {
	RESTRICT_ENV_USER,
	RESTRICT_ENV_CHROOT,
	RESTRICT_ENV_SETUID,
	RESTRICT_ENV_SETGID,
	RESTRICT_ENV_SETEXTRAGROUPS,
	RESTRICT_ENV_GID_FIRST,
	RESTRICT_ENV_GID_LAST,

	RESTRICT_ENV_COUNT
};

static const char *restrict_env_strings[RESTRICT_ENV_COUNT] = {
	"RESTRICT_USER",
	"RESTRICT_CHROOT",
	"RESTRICT_SETUID",
	"RESTRICT_SETGID",
	"RESTRICT_SETEXTRAGROUPS",
	"RESTRICT_GID_FIRST",
	"RESTRICT_GID_LAST"
};

static void renv_add(ARRAY_TYPE(const_string) *env, enum restrict_env key,
		     const char *value)
{
	envarr_add(env, restrict_env_strings[key], value);
}

void restrict_access_set_env(ARRAY_TYPE(const_string) *env,
			     const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir,
			     gid_t first_valid_gid, gid_t last_valid_gid,
			     const char *extra_groups)
{
	if (user != NULL && *user != '\0')
		renv_add(env, RESTRICT_ENV_USER, user);
	if (chroot_dir != NULL && *chroot_dir != '\0')
		renv_add(env, RESTRICT_ENV_CHROOT, chroot_dir);

	renv_add(env, RESTRICT_ENV_SETUID, dec2str(uid));
	renv_add(env, RESTRICT_ENV_SETGID, dec2str(gid));
	if (extra_groups != NULL && *extra_groups != '\0')
		renv_add(env, RESTRICT_ENV_SETEXTRAGROUPS, extra_groups);

	if (first_valid_gid != 0)
		renv_add(env, RESTRICT_ENV_GID_FIRST, dec2str(first_valid_gid));
	if (last_valid_gid != 0)
		renv_add(env, RESTRICT_ENV_GID_LAST, dec2str(last_valid_gid));
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

static bool drop_restricted_groups(const char *const *env_values,
				   gid_t *gid_list, unsigned int *gid_count,
				   bool *have_root_group)
{
	/* @UNSAFE */
	gid_t first_valid, last_valid;
	const char *env;
	unsigned int i, used;

	env = env_values[RESTRICT_ENV_GID_FIRST];
	first_valid = env == NULL ? 0 : (gid_t)strtoul(env, NULL, 10);
	env = env_values[RESTRICT_ENV_GID_LAST];
	last_valid = env == NULL ? (gid_t)-1 : (gid_t)strtoul(env, NULL, 10);

	for (i = 0, used = 0; i < *gid_count; i++) {
		if (gid_list[i] >= first_valid &&
		    (last_valid == (gid_t)-1 || gid_list[i] <= last_valid)) {
			if (gid_list[i] == 0)
				*have_root_group = TRUE;
			gid_list[used++] = gid_list[i];
		}
	}
	if (*gid_count == used)
		return FALSE;
	*gid_count = used;
	return TRUE;
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

static void fix_groups_list(const char *const *env_values, gid_t egid,
			    bool preserve_existing, bool *have_root_group)
{
	gid_t *gid_list;
	const char *const *tmp, *extra_groups, *empty = NULL;
	unsigned int gid_count;

	extra_groups = env_values[RESTRICT_ENV_SETEXTRAGROUPS];
	tmp = extra_groups == NULL ? &empty :
		t_strsplit_spaces(extra_groups, ", ");

	if (preserve_existing) {
		gid_list = get_groups_list(&gid_count);
		if (!drop_restricted_groups(env_values, gid_list, &gid_count,
					    have_root_group) &&
		    *tmp == NULL) {
			/* nothing dropped, no extra groups to grant. */
			return;
		}
	} else {
		/* Some OSes don't like an empty groups list,
		   so use the effective GID as the only one. */
		gid_list = t_new(gid_t, 2);
		gid_list[0] = egid;
		gid_count = 1;
	}

	/* add extra groups to gids list */
	for (; *tmp != NULL; tmp++) {
		if (!t_try_realloc(gid_list, (gid_count+1) * sizeof(gid_t)))
			i_unreached();
		gid_list[gid_count++] = get_group_id(*tmp);
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

void restrict_access_by_env(ARRAY_TYPE(const_string) *envarr,
			    bool disallow_root)
{
	const char *env_values[RESTRICT_ENV_COUNT], *const *envs, *env;
	const char *home = NULL;
	unsigned int i, j, count, len;
	gid_t gid;
	uid_t uid;
	bool is_root, have_root_group, preserve_groups = FALSE;

	if (envarr == NULL) {
		/* use environment */
		for (i = 0; i < RESTRICT_ENV_COUNT; i++)
			env_values[i] = getenv(restrict_env_strings[i]);
		home = getenv("HOME");
	} else {
		envs = array_get(envarr, &count);
		memset(env_values, 0, sizeof(env_values));
		for (i = 0; i < count; i++) {
			for (j = 0; j < RESTRICT_ENV_COUNT; j++) {
				len = strlen(restrict_env_strings[j]);
				if (strncmp(envs[i], restrict_env_strings[j],
					    len) == 0 &&
				    envs[i][len] == '=')
					env_values[j] = envs[i] + len + 1;
			}
			if (strncmp(envs[i], "HOME=", 5) == 0)
				home = envs[i] + 5;
		}
	}
	is_root = geteuid() == 0;

	/* set the primary group */
	env = env_values[RESTRICT_ENV_SETGID];
	gid = env == NULL || *env == '\0' ? (gid_t)-1 :
		(gid_t)strtoul(env, NULL, 10);
	have_root_group = gid == 0;
	if (gid != (gid_t)-1 && (gid != getgid() || gid != getegid())) {
		if (setgid(gid) != 0) {
			i_fatal("setgid(%s) failed with euid=%s, egid=%s: %m",
				dec2str(gid), dec2str(geteuid()),
				dec2str(getegid()));
		}
	}

	/* set system user's groups */
	env = env_values[RESTRICT_ENV_USER];
	if (env != NULL && *env != '\0' && is_root) {
		if (initgroups(env, gid) < 0) {
			i_fatal("initgroups(%s, %s) failed: %m",
				env, dec2str(gid));
		}
		preserve_groups = TRUE;
	}

	/* add extra groups. if we set system user's groups, drop the
	   restricted groups at the same time. */
	if (is_root) {
		T_FRAME(
			fix_groups_list(env_values, gid, preserve_groups,
					&have_root_group);
		);
	}

	/* chrooting */
	env = env_values[RESTRICT_ENV_CHROOT];
	if (env != NULL && *env != '\0') {
		/* kludge: localtime() must be called before chroot(),
		   or the timezone isn't known */
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
	env = env_values[RESTRICT_ENV_SETUID];
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

	env = env_values[RESTRICT_ENV_GID_FIRST];
	if ((!have_root_group || (env != NULL && atoi(env) != 0)) && uid != 0) {
		if (getgid() == 0 || getegid() == 0 || setgid(0) == 0) {
			if (gid == 0)
				i_fatal("GID 0 isn't permitted");
			i_fatal("We couldn't drop root group privileges "
				"(wanted=%s, gid=%s, egid=%s)", dec2str(gid),
				dec2str(getgid()), dec2str(getegid()));
		}
	}
}
