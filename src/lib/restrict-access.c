/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "restrict-access.h"
#include "env-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <grp.h>

#define HARD_MAX_GROUPS 10240

#ifndef NGROUPS_MAX
#  define NGROUPS_MAX 128
#endif

void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir,
			     gid_t first_valid_gid, gid_t last_valid_gid)
{
	if (user != NULL && *user != '\0')
		env_put(t_strconcat("RESTRICT_USER=", user, NULL));
	if (chroot_dir != NULL && *chroot_dir != '\0')
		env_put(t_strconcat("RESTRICT_CHROOT=", chroot_dir, NULL));

	env_put(t_strdup_printf("RESTRICT_SETUID=%s", dec2str(uid)));
	env_put(t_strdup_printf("RESTRICT_SETGID=%s", dec2str(gid)));

	if (first_valid_gid != 0) {
		env_put(t_strdup_printf("RESTRICT_GID_FIRST=%s",
					dec2str(first_valid_gid)));
	}
	if (last_valid_gid != 0) {
		env_put(t_strdup_printf("RESTRICT_GID_LAST=%s",
					dec2str(last_valid_gid)));
	}
}

static void drop_restricted_groups(void)
{
	/* @UNSAFE */
	const char *env;
	gid_t *gid_list, first_valid_gid, last_valid_gid;
	int ret, i, gid_count;

	env = getenv("RESTRICT_GID_FIRST");
	first_valid_gid = env == NULL ? 0 : (gid_t)atol(env);
	env = getenv("RESTRICT_GID_LAST");
	last_valid_gid = env == NULL ? 0 : (gid_t)atol(env);

	if (first_valid_gid == 0 && last_valid_gid == 0)
		return;

	gid_count = NGROUPS_MAX;
	gid_list = t_buffer_get(sizeof(gid_t) * gid_count);
	while ((ret = getgroups(gid_count, gid_list)) < 0) {
		if (errno != EINVAL ||
		    gid_count < HARD_MAX_GROUPS)
			i_fatal("getgroups() failed: %m");

		gid_count *= 2;
		gid_list = t_buffer_reget(gid_list, sizeof(gid_t) * gid_count);
	}

	gid_count = 0;
	for (i = 0; i < ret; i++) {
		if (gid_list[i] >= first_valid_gid &&
		    (last_valid_gid == 0 || gid_list[i] <= last_valid_gid))
			gid_list[gid_count++] = gid_list[i];
	}

	if (ret != gid_count) {
		/* it did contain 0, remove it */
		if (setgroups(gid_count, gid_list) < 0)
			i_fatal("setgroups() failed: %m");
	}
}

void restrict_access_by_env(int disallow_root)
{
	const char *env;
	gid_t gid;
	uid_t uid;

	/* groups - the getgid() checks are just so we don't fail if we're
	   not running as root and try to just use our own GID. Do this
	   before chrooting so initgroups() actually works. */
	env = getenv("RESTRICT_SETGID");
	gid = env == NULL ? 0 : (gid_t)atol(env);
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

                        drop_restricted_groups();
		}
	}

	/* chrooting */
	env = getenv("RESTRICT_CHROOT");
	if (env != NULL) {
		/* kludge: localtime() must be called before chroot(),
		   or the timezone isn't known */
		time_t t = 0;
		(void)localtime(&t);

		if (chroot(env) != 0)
			i_fatal("chroot(%s) failed: %m", env);

		if (chdir("/") != 0)
			i_fatal("chdir(/) failed: %m");
	}

	/* uid last */
	env = getenv("RESTRICT_SETUID");
	uid = env == NULL ? 0 : (uid_t)atol(env);
	if (uid != 0) {
		if (setuid(uid) != 0)
			i_fatal("setuid(%s) failed: %m", dec2str(uid));
	}

	/* verify that we actually dropped the privileges */
	if (uid != 0 || disallow_root) {
		if (setuid(0) == 0)
			i_fatal("We couldn't drop root privileges");
	}

	if ((gid != 0 && uid != 0) || disallow_root) {
		if (getgid() == 0 || getegid() == 0 || setgid(0) == 0)
			i_fatal("We couldn't drop root group privileges");
	}
}
