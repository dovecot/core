#ifndef NUMPACK_H
#define NUMPACK_H

/* Numbers are stored by 7 bits at a time. The highest bit specifies if the
   number continues to next byte. */

void numpack_encode(buffer_t *buf, uint64_t num);
int numpack_decode(const uint8_t **p, const uint8_t *end, uint64_t *num_r);

#endif
