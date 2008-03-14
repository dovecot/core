#ifndef IMAP_MESSAGESET_H
#define IMAP_MESSAGESET_H

#include "seq-range-array.h"

int imap_messageset_parse(ARRAY_TYPE(seq_range) *dest, const char *messageset);

#endif
