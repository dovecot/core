#ifndef STRNUM_H
#define STRNUM_H

/* str_to_*() functions return 0 if string is nothing more than a valid number
   in valid range. Otherwise -1 is returned and num_r is left untouched

   str_parse_*() helpers do not require the number to be the entire string
   and pass back the pointer just past a valid parsed integer in endp_r if
   it is non-NULL. What is written to endp_r in error cases is undefined.
*/

/*
 * Unsigned decimal
 */

int str_to_uint(const char *str, unsigned int *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint(const char *str, unsigned int *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ulong(const char *str, unsigned long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ulong(const char *str, unsigned long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ullong(const char *str, unsigned long long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ullong(const char *str, unsigned long long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint32(const char *str, uint32_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint32(const char *str, uint32_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint64(const char *str, uint64_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint64(const char *str, uint64_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uintmax(const char *str, uintmax_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uintmax(const char *str, uintmax_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

/* Returns TRUE if str is a valid unsigned number that equals to num. */
bool str_uint_equals(const char *str, uintmax_t num);

/*
 * Unsigned hexadecimal
 */

int str_to_uint_hex(const char *str, unsigned int *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint_hex(const char *str, unsigned int *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ulong_hex(const char *str, unsigned long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ulong_hex(const char *str, unsigned long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ullong_hex(const char *str, unsigned long long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ullong_hex(const char *str, unsigned long long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint32_hex(const char *str, uint32_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint32_hex(const char *str, uint32_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint64_hex(const char *str, uint64_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint64_hex(const char *str, uint64_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uintmax_hex(const char *str, uintmax_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uintmax_hex(const char *str, uintmax_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

/*
 * Unsigned octal
 */

int str_to_uint_oct(const char *str, unsigned int *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint_oct(const char *str, unsigned int *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ulong_oct(const char *str, unsigned long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ulong_oct(const char *str, unsigned long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_ullong_oct(const char *str, unsigned long long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_ullong_oct(const char *str, unsigned long long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint32_oct(const char *str, uint32_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint32_oct(const char *str, uint32_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uint64_oct(const char *str, uint64_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uint64_oct(const char *str, uint64_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_uintmax_oct(const char *str, uintmax_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uintmax_oct(const char *str, uintmax_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

/*
 * Signed
 */

int str_to_int(const char *str, int *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_int(const char *str, int *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_long(const char *str, long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_long(const char *str, long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_llong(const char *str, long long *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_llong(const char *str, long long *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_int32(const char *str, int32_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_int32(const char *str, int32_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_int64(const char *str, int64_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_int64(const char *str, int64_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_intmax(const char *str, intmax_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_intmax(const char *str, intmax_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

/*
 * Special numeric types
 */

int str_to_uid(const char *str, uid_t *num_r)
	ATTR_WARN_UNUSED_RESULT;

int str_to_gid(const char *str, gid_t *num_r)
	ATTR_WARN_UNUSED_RESULT;

int str_to_pid(const char *str, pid_t *num_r)
	ATTR_WARN_UNUSED_RESULT;

int str_to_ino(const char *str, ino_t *num_r)
	ATTR_WARN_UNUSED_RESULT;

int str_to_uoff(const char *str, uoff_t *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_parse_uoff(const char *str, uoff_t *num_r,
	const char **endp_r) ATTR_WARN_UNUSED_RESULT ATTR_NULL(3);

int str_to_time(const char *str, time_t *num_r)
	ATTR_WARN_UNUSED_RESULT;

/*
 * Floating point types
 *
 * Note: These use strto[fd](), which have locale-dependent behavior. However,
 * Dovecot never calls setlocale(), so the locale is always C.
 */
int str_to_float(const char *str, float *num_r)
	ATTR_WARN_UNUSED_RESULT;
int str_to_double(const char *str, double *num_r)
	ATTR_WARN_UNUSED_RESULT;

/*
 * Utility
 */

/* Return TRUE if all characters in string are numbers.
   Stop when `end_char' is found from string. */
bool str_is_numeric(const char *str, char end_char) ATTR_PURE;

/* Return TRUE when string has one or more numbers, followed
   with zero or one dot, followed with at least one number. */
bool str_is_float(const char *str, char end_char) ATTR_PURE;

/* Returns human readable string about what is wrong with the string.
   This function assumes that str_to_*() had already returned -1 for the
   string. */
const char *str_num_error(const char *str);

#endif
