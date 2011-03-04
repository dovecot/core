/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "strnum.h"

bool str_is_numeric(const char *str, char end_char)
{
	if (*str == '\0' || *str == end_char)
		return FALSE;

	while (*str != '\0' && *str != end_char) {
		if (*str < '0' || *str > '9')
			return FALSE;
		str++;
	}

	return TRUE;
}

int str_to_uint(const char *str, unsigned int *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (unsigned int)-1)
		return -1;
	*num_r = (unsigned int)l;
	return 0;
}

int str_to_ulong(const char *str, unsigned long *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (unsigned long)-1)
		return -1;
	*num_r = (unsigned long)l;
	return 0;
}

int str_to_ullong(const char *str, unsigned long long *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (unsigned long long)-1)
		return -1;
	*num_r = (unsigned long long)l;
	return 0;
}

int str_to_uint32(const char *str, uint32_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (uint32_t)-1)
		return -1;
	*num_r = (uint32_t)l;
	return 0;
}

int str_to_uint64(const char *str, uint64_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (uint64_t)-1)
		return -1;
	*num_r = (uint64_t)l;
	return 0;
}

int str_to_uintmax(const char *str, uintmax_t *num_r)
{
	uintmax_t next, n = 0;

	if (*str < '0' || *str > '9')
		return -1;

	for (; *str >= '0' && *str <= '9'; str++) {
		next = n*10;
		if (next < n) {
			/* overflow */
			return -1;
		}
		n = next + (*str - '0');
	}
	if (*str != '\0')
		return -1;
	*num_r = n;
	return 0;
}

int str_to_int(const char *str, int *num_r)
{
	intmax_t l;

	if (str_to_intmax(str, &l) < 0)
		return -1;

	if (l < INT_MIN || l > INT_MAX)
		return -1;
	*num_r = (int)l;
	return 0;
}

int str_to_long(const char *str, long *num_r)
{
	intmax_t l;

	if (str_to_intmax(str, &l) < 0)
		return -1;

	if (l < LONG_MIN || l > LONG_MAX)
		return -1;
	*num_r = (long)l;
	return 0;
}

int str_to_llong(const char *str, long long *num_r)
{
	intmax_t l;

	if (str_to_intmax(str, &l) < 0)
		return -1;

	if (l < LLONG_MIN || l > LLONG_MAX)
		return -1;
	*num_r = (long long)l;
	return 0;
}

int str_to_intmax(const char *str, intmax_t *num_r)
{
	bool neg = FALSE;
	uintmax_t l;

	if (*str == '-') {
		neg = TRUE;
		str++;
	}
	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (!neg) {
		if (l > INTMAX_MAX)
			return -1;
		*num_r = (intmax_t)l;
	} else {
		if (l > UINTMAX_MAX - (UINTMAX_MAX + INTMAX_MIN))
			return -1;
		*num_r = (intmax_t)-l;
	}
	return 0;
}

static int verify_xid(uintmax_t l, unsigned int result_size)
{
	unsigned int result_bits;

	/* we assume that result is a signed type,
	   but that it can never be negative */
	result_bits = result_size*CHAR_BIT - 1;
	if ((l >> result_bits) != 0)
		return -1;
	return 0;
}

int str_to_uid(const char *str, uid_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (verify_xid(l, sizeof(*num_r)) < 0)
		return -1;
	*num_r = (uid_t)l;
	return 0;
}

int str_to_gid(const char *str, gid_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	/* OS X uses negative GIDs */
#ifndef __APPLE__
	if (verify_xid(l, sizeof(*num_r)) < 0)
		return -1;
#endif
	*num_r = (gid_t)l;
	return 0;
}

int str_to_pid(const char *str, pid_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (verify_xid(l, sizeof(*num_r)) < 0)
		return -1;
	*num_r = (pid_t)l;
	return 0;
}

int str_to_uoff(const char *str, uoff_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (uoff_t)-1)
		return -1;
	*num_r = (uoff_t)l;
	return 0;
}

bool str_uint_equals(const char *str, uintmax_t num)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return FALSE;
	return l == num;
}

const char *str_num_error(const char *str)
{
	if (*str == '-') {
		if (!str_is_numeric(str + 1, '\0'))
			return "Not a valid number";
		return "Number too small";
	} else {
		if (!str_is_numeric(str, '\0'))
			return "Not a valid number";
		return "Number too large";
	}
}
