/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "config.h"
#undef HAVE_CONFIG_H

/* Linux needs the _XOPEN_SOURCE define, but others don't. It needs to be
   defined before unistd.h, so we need the above config.h include hack.. */
#ifdef PREAD_WRAPPERS
#  define _XOPEN_SOURCE 500 /* Linux */
#endif

#define IN_COMPAT_C
#include "lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#ifdef HAVE_INTTYPES_H
#  include <inttypes.h> /* for strtoimax() and strtoumax() */
#endif

#ifndef INADDR_NONE
#  define INADDR_NONE INADDR_BROADCAST
#endif

#if !defined (HAVE_STRCASECMP) && !defined (HAVE_STRICMP)
int i_my_strcasecmp(const char *s1, const char *s2)
{
	while (*s1 != '\0' && i_toupper(*s1) == i_toupper(*s2)) {
		s1++; s2++;
	}

        return i_toupper(*s1) - i_toupper(*s2);
}

int i_my_strncasecmp(const char *s1, const char *s2, size_t max_chars)
{
	while (max_chars > 1 && *s1 != '\0' &&
	       i_toupper(*s1) == i_toupper(*s2)) {
		s1++; s2++; max_chars--;
	}

        return i_toupper(*s1) - i_toupper(*s2);
}
#endif

#ifndef HAVE_INET_ATON
int i_my_inet_aton(const char *cp, struct in_addr *inp)
{
	in_addr_t addr;

	addr = inet_addr(cp);
	if (addr == INADDR_NONE)
		return 0;

	inp->s_addr = addr;
        return 1;
}
#endif

#ifndef HAVE_VSYSLOG
void i_my_vsyslog(int priority, const char *format, va_list args)
{
	T_BEGIN {
		syslog(priority, "%s", t_strdup_vprintf(format, args));
	} T_END;
}
#endif

#ifndef HAVE_GETPAGESIZE
int i_my_getpagesize(void)
{
#ifdef _SC_PAGESIZE
	return sysconf(_SC_PAGESIZE);
#else
#  ifdef __GNUC__
#    warning Guessing page size to be 4096
#  endif
	return 4096;
#endif
}
#endif

#ifndef HAVE_WRITEV
ssize_t i_my_writev(int fd, const struct iovec *iov, int iov_len)
{
	size_t written;
	ssize_t ret;
	int i;

	written = 0;
	for (i = 0; i < iov_len; i++, iov++) {
		ret = write(fd, iov->iov_base, iov->iov_len);
		if (ret < 0)
			return -1;

		written += ret;
		if ((size_t)ret != iov->iov_len)
			break;
	}

	if (written > SSIZE_T_MAX) {
		errno = ERANGE;
		return -1;
	}

	return (ssize_t)written;
}
#endif

#if !defined(HAVE_PREAD) || defined(PREAD_BROKEN)
ssize_t i_my_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret;
	off_t old_offset;

	old_offset = lseek(fd, 0, SEEK_CUR);
	if (old_offset == -1)
		return -1;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;

	ret = read(fd, buf, count);
	if (ret < 0)
		return -1;

	if (lseek(fd, old_offset, SEEK_SET) < 0)
		return -1;
	return ret;
}

ssize_t i_my_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t ret;
	off_t old_offset;

	old_offset = lseek(fd, 0, SEEK_CUR);
	if (old_offset == -1)
		return -1;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -1;

	ret = write(fd, buf, count);
	if (ret < 0)
		return -1;

	if (lseek(fd, old_offset, SEEK_SET) < 0)
		return -1;
	return ret;
}
#elif defined(PREAD_WRAPPERS)

ssize_t i_my_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t ret;

	ret = pread(fd, buf, count, offset);
	return ret;
}

ssize_t i_my_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return pwrite(fd, buf, count, offset);
}
#endif

#ifndef HAVE_SETEUID
int i_my_seteuid(uid_t euid)
{
#ifdef HAVE_SETREUID
	/* HP-UX at least doesn't have seteuid() but has setreuid() */
	return setreuid(-1, euid);
#else
#  error Missing seteuid functionality
#endif
}
#endif

#ifndef HAVE_SETEGID
int i_my_setegid(gid_t egid)
{
#ifdef HAVE_SETRESGID
	/* HP-UX at least doesn't have setegid() but has setresgid() */
	return setresgid(-1, egid, -1);
#else
#  error Missing setegid functionality
#endif
}
#endif

#ifndef HAVE_LIBGEN_H
char *i_my_basename(char *path)
{
	char *p;

	/* note that this isn't POSIX-compliant basename() replacement.
	   too much trouble without any gain. */
	p = strrchr(path, '/');
	return p == NULL ? path : p + 1;
}
#endif

#ifndef HAVE_STRTOULL
unsigned long long int i_my_strtoull(const char *nptr, char **endptr, int base)
{
#ifdef HAVE_STRTOUMAX
	return strtoumax(nptr, endptr, base);
#elif defined(HAVE_STRTOUQ)
	return strtouq(nptr, endptr, base);
#else
	unsigned long ret = 0;

	/* we support only base-10 in our fallback implementation.. */
	i_assert(base == 10);

	for (; *nptr != '\0'; nptr++) {
		if (*nptr < '0' || *nptr > '9')
			break;
		ret = ret * 10 + (*nptr - '0');
	}
	if (endptr != NULL)
		*endptr = (char *)nptr;
	return ret;
#endif
}
#endif

#ifndef HAVE_STRTOLL
unsigned long long int i_my_strtoll(const char *nptr, char **endptr, int base)
{
#ifdef HAVE_STRTOIMAX 
	return strtoimax(nptr, endptr, base);
#elif defined (HAVE_STRTOQ)
	return strtoq(nptr, endptr, base);
#else
	i_panic("strtoll() not implemented");
#endif
}
#endif

#ifdef HAVE_OLD_VSNPRINTF
#undef vsnprintf
int i_my_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	size_t tmp_size;
	char *tmp;
	int ret;

	/* On overflow HP-UX returns -1, IRIX and Tru64 return size-1. */
	ret = vsnprintf(str, size, format, ap);
	if (ret >= 0 && (size_t)ret+1 != size)
		return ret;

	/* see if data stack has enough available space for it */
	tmp_size = t_get_bytes_available();
	if (tmp_size > size) {
		tmp = t_buffer_get(tmp_size);
		ret = vsnprintf(tmp, tmp_size, format, ap);
		if (ret >= 0 && (size_t)ret+1 != tmp_size) {
			if (size > 0) {
				memcpy(str, tmp, size-1);
				str[size-1] = '\0';
			}
			return ret;
		}
	} else {
		tmp_size = size;
	}

	/* try to allocate enough memory to get it to fit. */
	do {
		tmp_size = nearest_power(tmp_size+1);
		tmp = i_malloc(tmp_size);
		ret = vsnprintf(tmp, tmp_size, format, ap);
		if (ret >= 0 && (size_t)ret+1 != tmp_size) {
			if (size > 0) {
				memcpy(str, tmp, size-1);
				str[size-1] = '\0';
			}
			i_free(tmp);
			return ret;
		}
		i_free(tmp);
	} while (tmp_size < 1024*1024);

	i_panic("my_vsnprintf(): Output string too big");
}
#endif

#ifndef HAVE_CLOCK_GETTIME
int i_my_clock_gettime(int clk_id, struct timespec *tp)
{
	struct timeval tv;

	i_assert(clk_id == CLOCK_REALTIME);

	/* fallback to using microseconds */
	if (gettimeofday(&tv, NULL) < 0)
		return -1;
	tp->tv_sec = tv.tv_sec;
	tp->tv_nsec = tv.tv_usec * 1000;
	return 0;
}
#endif
