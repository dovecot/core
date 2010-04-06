#ifndef STRNUM_H
#define STRNUM_H

/* Return TRUE if all characters in string are numbers.
   Stop when `end_char' is found from string. */
bool str_is_numeric(const char *str, char end_char) ATTR_PURE;

/* str_to_*() functions return 0 if string is valid number in valid range.
   Otherwise -1 is returned and num_r is left untouched */

int str_to_uint(const char *str, unsigned int *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_ulong(const char *str, unsigned long *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_ullong(const char *str, unsigned long long *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_uint32(const char *str, uint32_t *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_uint64(const char *str, uint64_t *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_uintmax(const char *str, uintmax_t *num_r) ATTR_WARN_UNUSED_RESULT;

int str_to_int(const char *str, int *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_long(const char *str, long *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_llong(const char *str, long long *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_intmax(const char *str, intmax_t *num_r) ATTR_WARN_UNUSED_RESULT;

int str_to_uid(const char *str, uid_t *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_gid(const char *str, gid_t *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_pid(const char *str, pid_t *num_r) ATTR_WARN_UNUSED_RESULT;
int str_to_uoff(const char *str, uoff_t *num_r) ATTR_WARN_UNUSED_RESULT;

/* Returns TRUE if str is a valid unsigned number that equals to num. */
bool str_uint_equals(const char *str, uintmax_t num);

/* Returns human readable string about what is wrong with the string.
   This function assumes that str_to_*() had already returned -1 for the
   string. */
const char *str_num_error(const char *str);

#endif
