/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

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

bool str_is_float(const char *str, char end_char)
{
	bool dot_seen = FALSE;
	bool num_seen = FALSE;

	if (*str == '\0' || *str == end_char)
		return FALSE;

	while (*str != '\0' && *str != end_char) {
		if (*str == '.') {
			if (dot_seen || !num_seen) return FALSE;
			dot_seen = TRUE;
			num_seen = FALSE;
			str++;
			/* enforce that number follows dot */
			continue;
		}
		if (*str < '0' || *str > '9')
			return FALSE;
		num_seen = TRUE;
		str++;
	}

	return num_seen;
}

/* 
 * Unsigned decimal
 */

#define STR_PARSE_U__TEMPLATE(name, type)                     \
int name(const char *str, type *num_r, const char **endp_r)   \
{                                                             \
	uintmax_t l;                                                \
	if (str_parse_uintmax(str, &l, endp_r) < 0 || l > (type)-1) \
		return -1;                                                \
	*num_r = (type)l;                                           \
	return 0;                                                   \
}

STR_PARSE_U__TEMPLATE(str_parse_uint, unsigned int)
STR_PARSE_U__TEMPLATE(str_parse_ulong, unsigned long)
STR_PARSE_U__TEMPLATE(str_parse_ullong, unsigned long long)
STR_PARSE_U__TEMPLATE(str_parse_uint32, uint32_t)
STR_PARSE_U__TEMPLATE(str_parse_uint64, uint64_t)

#define STR_TO_U__TEMPLATE(name, type)                        \
int name(const char *str, type *num_r)                        \
{                                                             \
	uintmax_t l;                                                \
	if (str_to_uintmax(str, &l) < 0 || l > (type)-1)            \
		return -1;                                                \
	*num_r = (type)l;                                           \
	return 0;                                                   \
}

STR_TO_U__TEMPLATE(str_to_uint, unsigned int)
STR_TO_U__TEMPLATE(str_to_ulong, unsigned long)
STR_TO_U__TEMPLATE(str_to_ullong, unsigned long long)
STR_TO_U__TEMPLATE(str_to_uint32, uint32_t)
STR_TO_U__TEMPLATE(str_to_uint64, uint64_t)

int str_parse_uintmax(const char *str, uintmax_t *num_r,
	const char **endp_r)
{
	uintmax_t n = 0;

	if (*str < '0' || *str > '9')
		return -1;

	for (; *str >= '0' && *str <= '9'; str++) {
		if (n >= ((uintmax_t)-1 / 10)) {
			if (n > (uintmax_t)-1 / 10)
				return -1;
			if ((uintmax_t)(*str - '0') > ((uintmax_t)-1 % 10))
				return -1;
		}
		n = n * 10 + (*str - '0');
	}
	if (endp_r != NULL)
		*endp_r = str;
	*num_r = n;
	return 0;
}
int str_to_uintmax(const char *str, uintmax_t *num_r)
{
	const char *endp;
	uintmax_t n;
	int ret = str_parse_uintmax(str, &n, &endp);
	if ((ret != 0) || (*endp != '\0'))
		return -1;
	*num_r = n;
	return 0;
}

bool str_uint_equals(const char *str, uintmax_t num)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return FALSE;
	return l == num;
}

/* 
 * Unsigned hexadecimal
 */

#define STR_PARSE_UHEX__TEMPLATE(name, type)                       \
int name(const char *str, type *num_r, const char **endp_r)        \
{                                                                  \
	uintmax_t l;                                                     \
	if (str_parse_uintmax_hex(str, &l, endp_r) < 0 || l > (type)-1)  \
		return -1;                                                     \
	*num_r = (type)l;                                                \
	return 0;                                                        \
}

STR_PARSE_UHEX__TEMPLATE(str_parse_uint_hex, unsigned int)
STR_PARSE_UHEX__TEMPLATE(str_parse_ulong_hex, unsigned long)
STR_PARSE_UHEX__TEMPLATE(str_parse_ullong_hex, unsigned long long)
STR_PARSE_UHEX__TEMPLATE(str_parse_uint32_hex, uint32_t)
STR_PARSE_UHEX__TEMPLATE(str_parse_uint64_hex, uint64_t)

#define STR_TO_UHEX__TEMPLATE(name, type)                          \
int name(const char *str, type *num_r)                             \
{                                                                  \
	uintmax_t l;                                                     \
	if (str_to_uintmax_hex(str, &l) < 0 || l > (type)-1)             \
		return -1;                                                     \
	*num_r = (type)l;                                                \
	return 0;                                                        \
}

STR_TO_UHEX__TEMPLATE(str_to_uint_hex, unsigned int)
STR_TO_UHEX__TEMPLATE(str_to_ulong_hex, unsigned long)
STR_TO_UHEX__TEMPLATE(str_to_ullong_hex, unsigned long long)
STR_TO_UHEX__TEMPLATE(str_to_uint32_hex, uint32_t)
STR_TO_UHEX__TEMPLATE(str_to_uint64_hex, uint64_t)

static inline int _str_parse_hex(const char ch,
	unsigned int *hex_r)
{
	switch (ch) {
	case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		*hex_r = (unsigned int)(ch - 'a' + 10);
		return 0;
	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		*hex_r = (unsigned int)(ch - 'A' + 10);
		return 0;
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		*hex_r = (unsigned int)(ch - '0');
		return 0;
	default:
		break;
	}
	return -1;
}
int str_parse_uintmax_hex(const char *str, uintmax_t *num_r,
	const char **endp_r)
{
	unsigned int hex;
	uintmax_t n = 0;

	if (_str_parse_hex(*str, &hex) < 0)
		return -1;

	do {
		if (n > (uintmax_t)-1 >> 4)
			return -1;
		n = (n << 4) + hex;
		str++;
	} while (_str_parse_hex(*str, &hex) >= 0);
	if (endp_r != NULL)
		*endp_r = str;
	*num_r = n;
	return 0;
}
int str_to_uintmax_hex(const char *str, uintmax_t *num_r)
{
	const char *endp;
	uintmax_t n;
	int ret = str_parse_uintmax_hex(str, &n, &endp);
	if ((ret != 0) || (*endp != '\0'))
		return -1;
	*num_r = n;
	return 0;
}

/* 
 * Unsigned octal
 */

#define STR_PARSE_UOCT__TEMPLATE(name, type)                       \
int name(const char *str, type *num_r, const char **endp_r)        \
{                                                                  \
	uintmax_t l;                                                     \
	if (str_parse_uintmax_oct(str, &l, endp_r) < 0 || l > (type)-1)  \
		return -1;                                                     \
	*num_r = (type)l;                                                \
	return 0;                                                        \
}

STR_PARSE_UOCT__TEMPLATE(str_parse_uint_oct, unsigned int)
STR_PARSE_UOCT__TEMPLATE(str_parse_ulong_oct, unsigned long)
STR_PARSE_UOCT__TEMPLATE(str_parse_ullong_oct, unsigned long long)
STR_PARSE_UOCT__TEMPLATE(str_parse_uint32_oct, uint32_t)
STR_PARSE_UOCT__TEMPLATE(str_parse_uint64_oct, uint64_t)

#define STR_TO_UOCT__TEMPLATE(name, type)                          \
int name(const char *str, type *num_r)                             \
{                                                                  \
	uintmax_t l;                                                     \
	if (str_to_uintmax_oct(str, &l) < 0 || l > (type)-1)             \
		return -1;                                                     \
	*num_r = (type)l;                                                \
	return 0;                                                        \
}

STR_TO_UOCT__TEMPLATE(str_to_uint_oct, unsigned int)
STR_TO_UOCT__TEMPLATE(str_to_ulong_oct, unsigned long)
STR_TO_UOCT__TEMPLATE(str_to_ullong_oct, unsigned long long)
STR_TO_UOCT__TEMPLATE(str_to_uint32_oct, uint32_t)
STR_TO_UOCT__TEMPLATE(str_to_uint64_oct, uint64_t)

int str_parse_uintmax_oct(const char *str, uintmax_t *num_r,
	const char **endp_r)
{
	uintmax_t n = 0;

	if (*str < '0' || *str > '7')
		return -1;

	for (; *str >= '0' && *str <= '7'; str++) {
		if (n > (uintmax_t)-1 >> 3)
			return -1;
		n = (n << 3) + (*str - '0');
	}
	if (endp_r != NULL)
		*endp_r = str;
	*num_r = n;
	return 0;
}
int str_to_uintmax_oct(const char *str, uintmax_t *num_r)
{
	const char *endp;
	uintmax_t n;
	int ret = str_parse_uintmax_oct(str, &n, &endp);
	if ((ret != 0) || (*endp != '\0'))
		return -1;
	*num_r = n;
	return 0;
}

/* 
 * Signed
 */

#define STR_PARSE_S__TEMPLATE(name, type, int_min, int_max)   \
int name(const char *str, type *num_r, const char **endp_r)	  \
{                                                             \
	intmax_t l;                                                 \
	if (str_parse_intmax(str, &l, endp_r) < 0)                  \
		return -1;                                                \
	if (l < int_min || l > int_max)                             \
		return -1;                                                \
	*num_r = (type)l;                                           \
	return 0;                                                   \
}

STR_PARSE_S__TEMPLATE(str_parse_int, int, INT_MIN, INT_MAX)
STR_PARSE_S__TEMPLATE(str_parse_long, long, LONG_MIN, LONG_MAX)
STR_PARSE_S__TEMPLATE(str_parse_llong, long long, LLONG_MIN, LLONG_MAX)
STR_PARSE_S__TEMPLATE(str_parse_int32, int32_t, INT32_MIN, INT32_MAX)
STR_PARSE_S__TEMPLATE(str_parse_int64, int64_t, INT64_MIN, INT64_MAX)

#define STR_TO_S__TEMPLATE(name, type, int_min, int_max)      \
int name(const char *str, type *num_r)                        \
{                                                             \
	intmax_t l;                                                 \
	if (str_to_intmax(str, &l) < 0)                             \
		return -1;                                                \
	if (l < int_min || l > int_max)                             \
		return -1;                                                \
	*num_r = (type)l;                                           \
	return 0;                                                   \
}

STR_TO_S__TEMPLATE(str_to_int, int, INT_MIN, INT_MAX)
STR_TO_S__TEMPLATE(str_to_long, long, LONG_MIN, LONG_MAX)
STR_TO_S__TEMPLATE(str_to_llong, long long, LLONG_MIN, LLONG_MAX)
STR_TO_S__TEMPLATE(str_to_int32, int32_t, INT32_MIN, INT32_MAX)
STR_TO_S__TEMPLATE(str_to_int64, int64_t, INT64_MIN, INT64_MAX)

int str_parse_intmax(const char *str, intmax_t *num_r,
	const char **endp_r)
{
	bool neg = FALSE;
	uintmax_t l;

	if (*str == '-') {
		neg = TRUE;
		str++;
	}
	if (str_parse_uintmax(str, &l, endp_r) < 0)
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
int str_to_intmax(const char *str, intmax_t *num_r)
{
	const char *endp;
	intmax_t n;
	int ret = str_parse_intmax(str, &n, &endp);
	if ((ret != 0) || (*endp != '\0'))
		return -1;
	*num_r = n;
	return 0;
}

/* 
 * Special numeric types
 */

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

int str_to_ino(const char *str, ino_t *num_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (verify_xid(l, sizeof(*num_r)) < 0)
		return -1;
	*num_r = (ino_t)l;
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

int str_to_time(const char *str, time_t *num_r)
{
	intmax_t l;

	if (str_to_intmax(str, &l) < 0)
		return -1;

	*num_r = (time_t)l;
	return 0;
}

STR_PARSE_U__TEMPLATE(str_parse_uoff, uoff_t)

/*
 * Error handling
 */

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
