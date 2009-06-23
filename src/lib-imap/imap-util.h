#ifndef IMAP_UTIL_H
#define IMAP_UTIL_H

#include "seq-range-array.h"

enum mail_flags;
struct imap_arg;

/* Write flags as a space separated string. */
void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords);
/* Parse system flag from a string, or return 0 if it's invalid. */
enum mail_flags imap_parse_system_flag(const char *str);

/* Write sequence range as IMAP sequence-set */
void imap_write_seq_range(string_t *dest, const ARRAY_TYPE(seq_range) *array);
/* Write IMAP args to given string. The string is mainly useful for humans. */
void imap_write_args(string_t *dest, const struct imap_arg *args);
/* Like imap_write_args(), but return the string allocated from data stack. */
const char *imap_args_to_str(const struct imap_arg *args);

#endif
