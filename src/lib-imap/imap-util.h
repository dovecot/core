#ifndef IMAP_UTIL_H
#define IMAP_UTIL_H

#include "seq-range-array.h"

enum mail_flags;

/* Write flags as a space separated string. */
void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords);

/* Write sequence range as IMAP sequence-set */
void imap_write_seq_range(string_t *dest, const ARRAY_TYPE(seq_range) *array);

#endif
