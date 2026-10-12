#ifndef IMAP_SEQSET_H
#define IMAP_SEQSET_H

#include "seq-range-array.h"

/* Parse IMAP sequence-set and store the result in dest. '*' is stored as
   (uint32_t)-1. Returns 0 if successful, -1 if input is invalid. */
int imap_seq_set_parse(const char *str, ARRAY_TYPE(seq_range) *dest);
/* Like imap_seq_set_parse(), but fail if '*' is used. */
int imap_seq_set_nostar_parse(const char *str, ARRAY_TYPE(seq_range) *dest);
/* Parse IMAP sequence-set where the order of the sequences matter, such as
   ESORT response. Each range is appended to dest as-is, so dest is in the
   input order and its ranges are neither merged nor sorted and may overlap.
   It's therefore not a valid seq-range-array and must not be passed to
   seq_range_array_*(). A descending range such as "5:1" is stored as 1:5. */
int imap_seq_set_ordered_parse(const char *str, ARRAY_TYPE(seq_range) *dest);

/* Parse IMAP seq-number / seq-range. */
int imap_seq_range_parse(const char *str, uint32_t *seq1_r, uint32_t *seq2_r);

#endif
