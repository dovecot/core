#ifndef IMAP_UTIL_H
#define IMAP_UTIL_H

#include "seq-range-array.h"
#include "mail-types.h"

struct imap_arg;

/* Write flags as a space separated string. */
void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords) ATTR_NULL(3);
/* Parse system flag from a string, or return 0 if it's invalid. */
enum mail_flags imap_parse_system_flag(const char *str);

/* Write sequence range as IMAP sequence-set */
void imap_write_seq_range(string_t *dest, const ARRAY_TYPE(seq_range) *array);
/* Write IMAP arg to the given string. Because IMAP_ARG_LITERAL_SIZE* have no
   content, they're written as "{size}\r\n<too large>". */
void imap_write_arg(string_t *dest, const struct imap_arg *arg);
/* Same as imap_write_arg(), but write all the args until EOL. */
void imap_write_args(string_t *dest, const struct imap_arg *args);
/* Write IMAP args in a human-readable format to given string (e.g. for
   logging). The output is a single valid UTF-8 line without control
   characters. Multi-line literals are replaced with a generic placeholder. */
void imap_write_args_for_human(string_t *dest, const struct imap_arg *args);
/* Like imap_write_args(), but return the string allocated from data stack. */
const char *imap_args_to_str(const struct imap_arg *args);

#endif
