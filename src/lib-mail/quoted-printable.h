#ifndef QUOTED_PRINTABLE_H
#define QUOTED_PRINTABLE_H

/* Translates quoted printable data into binary. dest must be at least the
   size of src, and may be same as src. Decoding errors are ignored.

   This function may be called multiple times for parsing the same stream.
   If src_pos is non-NULL, it's updated to first non-translated character in
   src. */
void quoted_printable_decode(const unsigned char *src, size_t src_size,
			     size_t *src_pos_r, buffer_t *dest);

#endif
