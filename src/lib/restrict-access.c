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

void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir)
{
	if (user != NULL && *user != '\0')
		env_put(t_strconcat("RESTRICT_USER=", user, NULL));
	if (chroot_dir != NULL && *chroot_dir != '\0')
		env_put(t_strconcat("RESTRICT_CHROOT=", chroot_dir, NULL));

	env_put(t_strdup_printf("RESTRICT_SETUID=%ld", (long) uid));
	env_put(t_strdup_printf("RESTRICT_SETGID=%ld", (long) gid));
}

void restrict_access_by_env(int disallow_root)
{
	const char *env;
	gid_t gid;
	uid_t uid;

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

	/* groups - the getgid() checks are just so we don't fail if we're
	   not running as root and try to just use our own GID. */
	env = getenv("RESTRICT_SETGID");
	gid = env == NULL ? 0 : (gid_t) atol(env);
	if (gid != 0 && (gid != getgid() || gid != getegid())) {
		if (setgid(gid) != 0)
			i_fatal("setgid(%ld) failed: %m", (long) gid);

		env = getenv("RESTRICT_USER");
		if (env == NULL) {
			/* user not known, use only this one group */
			(void)setgroups(1, &gid);
		} else {
			if (initgroups(env, gid) != 0) {
				i_fatal("initgroups(%s, %ld) failed: %m",
					env, (long) gid);
			}
		}
	}

	/* uid last */
	env = getenv("RESTRICT_SETUID");
	uid = env == NULL ? 0 : (uid_t) atol(env);
	if (uid != 0) {
		if (setuid(uid) != 0)
			i_fatal("setuid(%ld) failed: %m", (long) uid);
	}

	/* verify that we actually dropped the privileges */
	if (uid != 0 || disallow_root) {
		if (setuid(0) == 0)
			i_fatal("We couldn't drop root privileges");
	}

	if (gid != 0 || disallow_root) {
		if (getgid() == 0 || getegid() == 0 || setgid(0) == 0)
			i_fatal("We couldn't drop root group privileges");
	}
}
