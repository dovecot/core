/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#define _POSIX_PTHREAD_SEMANTICS /* for Solaris */
#include "lib.h"
#include "ipwd.h"

#include <unistd.h>

#define PWBUF_MIN_SIZE 128
#define GRBUF_MIN_SIZE 128

static void *pwbuf = NULL, *grbuf = NULL;
static size_t pwbuf_size, grbuf_size;

static void pw_init(void)
{
	size_t old_pwbuf_size = pwbuf_size;

	if (pwbuf == NULL || errno == ERANGE) {
		pwbuf_size = nearest_power(old_pwbuf_size + 1);
		if (pwbuf_size < PWBUF_MIN_SIZE)
			pwbuf_size = PWBUF_MIN_SIZE;
		pwbuf = i_realloc(pwbuf, old_pwbuf_size, pwbuf_size);
	}
}

static void gr_init(void)
{
	size_t old_grbuf_size = grbuf_size;

	if (grbuf == NULL || errno == ERANGE) {
		grbuf_size = nearest_power(old_grbuf_size + 1);
		if (grbuf_size < PWBUF_MIN_SIZE)
			grbuf_size = PWBUF_MIN_SIZE;
		grbuf = i_realloc(grbuf, old_grbuf_size, grbuf_size);
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

	errno = 0;
	do {
		pw_init();
		errno = getpwnam_r(name, pwd_r, pwbuf, pwbuf_size, &result);
	} while (errno == ERANGE);
	if (result != NULL)
		return 1;
	if (errno == EINVAL) {
		/* FreeBSD fails here when name="user@domain" */
		return 0;
	}
	return errno == 0 ? 0 : -1;
}

int i_getpwuid(uid_t uid, struct passwd *pwd_r)
{
	struct passwd *result;

	errno = 0;
	do {
		pw_init();
		errno = getpwuid_r(uid, pwd_r, pwbuf, pwbuf_size, &result);
	} while (errno == ERANGE);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}

int i_getgrnam(const char *name, struct group *grp_r)
{
	struct group *result;

	errno = 0;
	do {
		gr_init();
		errno = getgrnam_r(name, grp_r, grbuf, grbuf_size, &result);
	} while (errno == ERANGE);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}

int i_getgrgid(gid_t gid, struct group *grp_r)
{
	struct group *result;

	errno = 0;
	do {
		gr_init();
		errno = getgrgid_r(gid, grp_r, grbuf, grbuf_size, &result);
	} while (errno == ERANGE);
	if (result != NULL)
		return 1;
	return errno == 0 ? 0 : -1;
}
