/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "env-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <grp.h>

void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
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

static gid_t *get_groups_list(int *gid_count_r)
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

static void drop_restricted_groups(bool *have_root_group)
{
	/* @UNSAFE */
	const char *env;
	gid_t *gid_list, first_valid_gid, last_valid_gid;
	int i, used, gid_count;

	env = getenv("RESTRICT_GID_FIRST");
	first_valid_gid = env == NULL ? 0 : (gid_t)strtoul(env, NULL, 10);
	env = getenv("RESTRICT_GID_LAST");
	last_valid_gid = env == NULL ? 0 : (gid_t)strtoul(env, NULL, 10);

	if (first_valid_gid == 0 && last_valid_gid == 0)
		return;

	t_push();
	gid_list = get_groups_list(&gid_count);

	for (i = 0, used = 0; i < gid_count; i++) {
		if (gid_list[i] >= first_valid_gid &&
		    (last_valid_gid == 0 || gid_list[i] <= last_valid_gid)) {
			if (gid_list[i] == 0)
				*have_root_group = TRUE;
			gid_list[used++] = gid_list[i];
		}
	}

	if (used != gid_count) {
		/* it did contain restricted groups, remove it */
		if (setgroups(used, gid_list) < 0) {
			i_fatal("Couldn't drop restricted groups: "
				"setgroups() failed: %m");
		}
	}
	t_pop();
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

static void grant_extra_groups(const char *groups)
{
	const char *const *tmp;
	gid_t *gid_list;
	int gid_count;

	t_push();
	tmp = t_strsplit(groups, ", ");
	gid_list = get_groups_list(&gid_count);
	for (; *tmp != NULL; tmp++) {
		if (**tmp == '\0')
			continue;

		if (!t_try_realloc(gid_list, (gid_count+1) * sizeof(gid_t)))
			i_unreached();
		gid_list[gid_count++] = get_group_id(*tmp);
	}

	if (setgroups(gid_count, gid_list) < 0) {
		i_fatal("Couldn't set mail_extra_groups: "
			"setgroups(%s) failed: %m", groups);
	}

	t_pop();
}

void restrict_access_by_env(bool disallow_root)
{
	const char *env;
	gid_t gid;
	uid_t uid;
	bool have_root_group;

	/* groups - the getgid() checks are just so we don't fail if we're
	   not running as root and try to just use our own GID. Do this
	   before chrooting so initgroups() actually works. */
	env = getenv("RESTRICT_SETGID");
	gid = env == NULL ? 0 : (gid_t)strtoul(env, NULL, 10);
	have_root_group = gid == 0;
	if (gid != 0 && (gid != getgid() || gid != getegid())) {
		if (setgid(gid) != 0)
			i_fatal("setgid(%s) failed: %m", dec2str(gid));

		env = getenv("RESTRICT_USER");
		if (env == NULL) {
			/* user not known, use only this one group */
			if (setgroups(1, &gid) < 0) {
				i_fatal("setgroups(%s) failed: %m",
					dec2str(gid));
			}
		} else {
			if (initgroups(env, gid) != 0) {
				i_fatal("initgroups(%s, %s) failed: %m",
					env, dec2str(gid));
			}

                        drop_restricted_groups(&have_root_group);
		}
	}

	/* grant additional groups to process */
	env = getenv("RESTRICT_SETEXTRAGROUPS");
	if (env != NULL && *env != '\0')
		grant_extra_groups(env);

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
	uid = env == NULL ? 0 : (uid_t)strtoul(env, NULL, 10);
	if (uid != 0) {
		if (setuid(uid) != 0)
			i_fatal("setuid(%s) failed: %m", dec2str(uid));
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
	if ((!have_root_group || (env != NULL && atoi(env) != 0)) && uid != 0) {
		if (getgid() == 0 || getegid() == 0 || setgid(0) == 0) {
			if (gid == 0)
				i_fatal("GID 0 isn't permitted");
			i_fatal("We couldn't drop root group privileges "
				"(wanted=%s, gid=%s, egid=%s)", dec2str(gid),
				dec2str(getgid()), dec2str(getegid()));
		}
	}

	/* clear the environment, so we don't fail if we get back here */
	env_put("RESTRICT_USER=");
	env_put("RESTRICT_CHROOT=");
	env_put("RESTRICT_SETUID=");
	env_put("RESTRICT_SETGID=");
	env_put("RESTRICT_SETEXTRAGROUPS=");
	env_put("RESTRICT_GID_FIRST=");
	env_put("RESTRICT_GID_LAST=");
}
