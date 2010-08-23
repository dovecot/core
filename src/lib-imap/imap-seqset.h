#ifndef IMAP_SEQSET_H
#define IMAP_SEQSET_H

#include "seq-range-array.h"

/* Parse IMAP sequence-set and store the result in dest. '*' is stored as
   (uint32_t)-1. Returns 0 if successful, -1 if input is invalid. */
int imap_seq_set_parse(const char *str, ARRAY_TYPE(seq_range) *dest);
/* Like imap_seq_set_parse(), but fail if '*' is used. */
int imap_seq_set_nostar_parse(const char *str, ARRAY_TYPE(seq_range) *dest);

/* Parse IMAP seq-number / seq-range. */
int imap_seq_range_parse(const char *str, uint32_t *seq1_r, uint32_t *seq2_r);

#endif
