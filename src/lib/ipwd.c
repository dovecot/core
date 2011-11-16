/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#define _POSIX_PTHREAD_SEMANTICS /* for Solaris */
#include "lib.h"
#include "ipwd.h"

#include <unistd.h>

#define DEFAULT_PWBUF_SIZE 16384
#define DEFAULT_GRBUF_SIZE 16384

static void *pwbuf = NULL, *grbuf = NULL;
static size_t pwbuf_size, grbuf_size;

static void pw_init(void)
{
	long size;

	if (pwbuf == NULL) {
		size = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (size < 0)
			size = DEFAULT_PWBUF_SIZE;

		pwbuf_size = size;
		pwbuf = i_malloc(pwbuf_size);
	}
}

static void gr_init(void)
{
	long size;

	if (grbuf == NULL) {
		size = sysconf(_SC_GETGR_R_SIZE_MAX);
		/* Some BSDs return too low value for this. instead of trying
		   to figure out exactly which, just make sure it's at least
		   a reasonable size. if the real size is smaller, it doesn't
		   matter much that we waste a few kilobytes of memory. */
		if (size < DEFAULT_GRBUF_SIZE)
			size = DEFAULT_GRBUF_SIZE;

		grbuf_size = size;
		grbuf = i_malloc(grbuf_size);
	}
}

void ipwd_deinit(void)
{
	i_free_and_null(pwbuf);
	i_free_and_null(grbuf);
}

int i_getpwnam(const char *name, struct passwd *pwd_r)
{
	struct passwd *result;

	pw_init();
	errno = getpwnam_r(name, pwd_r, pwbuf, pwbuf_size, &result);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}

int i_getpwuid(uid_t uid, struct passwd *pwd_r)
{
	struct passwd *result;

	pw_init();
	errno = getpwuid_r(uid, pwd_r, pwbuf, pwbuf_size, &result);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}

int i_getgrnam(const char *name, struct group *grp_r)
{
	struct group *result;

	gr_init();
	errno = getgrnam_r(name, grp_r, grbuf, grbuf_size, &result);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}

int i_getgrgid(gid_t gid, struct group *grp_r)
{
	struct group *result;

	gr_init();
	errno = getgrgid_r(gid, grp_r, grbuf, grbuf_size, &result);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}
