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

#include <stdlib.h>
#include <unistd.h>
#include <grp.h>

void restrict_access_set_env(const char *user, uid_t uid, gid_t gid,
			     const char *chroot_dir)
{
	if (user != NULL && *user != '\0')
		putenv((char *) t_strconcat("USER=", user, NULL));
	if (chroot_dir != NULL && *chroot_dir != '\0')
		putenv((char *) t_strconcat("CHROOT=", chroot_dir, NULL));

	putenv((char *) t_strdup_printf("SETUID=%ld", (long) uid));
	putenv((char *) t_strdup_printf("SETGID=%ld", (long) gid));
}

void restrict_access_by_env(void)
{
	const char *env;
	gid_t gid;
	uid_t uid;

	/* chrooting */
	env = getenv("CHROOT");
	if (env != NULL) {
		if (chroot(env) != 0)
			i_fatal("chroot(%s) failed: %m", env);

		if (chdir("/") != 0)
			i_fatal("chdir(/) failed: %m");
	}

	/* groups - the getgid() checks are just so we don't fail if we're
	   not running as root and try to just use our own GID. */
	env = getenv("SETGID");
	gid = env == NULL ? 0 : (gid_t) atol(env);
	if (gid != 0 && (gid != getgid() || gid != getegid())) {
		if (setgid(gid) != 0)
			i_fatal("setgid(%ld) failed: %m", (long) gid);

		env = getenv("USER");
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
	env = getenv("SETUID");
	uid = env == NULL ? 0 : (uid_t) atol(env);
	if (uid != 0) {
		if (setuid(uid) != 0)
			i_fatal("setuid(%ld) failed: %m", (long) uid);

		/* just extra verification */
#ifdef HAVE_SETREUID
		if (setreuid((uid_t)-1, 0) == 0)
#else
		if (setuid(0) == 0)
#endif
			i_fatal("We couldn't drop root privileges");
	}
}
