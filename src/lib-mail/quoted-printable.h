#ifndef QUOTED_PRINTABLE_H
#define QUOTED_PRINTABLE_H

/* Decode MIME "Q" encoding. */
int quoted_printable_q_decode(const unsigned char *src, size_t src_size,
			      buffer_t *dest);

#endif
