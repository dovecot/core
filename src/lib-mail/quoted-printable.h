#ifndef QUOTED_PRINTABLE_H
#define QUOTED_PRINTABLE_H

/* Translates quoted printable data into binary. dest must be at least the
   size of src, and may be same as src. Returns 0 if input was valid, -1 if
   there were some decoding errors (which were skipped over). LFs without
   preceding CR are returned as CRLF (but =0A isn't).

   This function may be called multiple times for parsing the same stream.
   src_pos is updated to first non-translated character in src. */
int quoted_printable_decode(const unsigned char *src, size_t src_size,
			    size_t *src_pos_r, buffer_t *dest);
/* Like quoted_printable_decode(), but handle src as the final block.
   This allows src to end without LF. */
int quoted_printable_decode_final(const unsigned char *src, size_t src_size,
				  size_t *src_pos_r, buffer_t *dest);
/* Decode MIME "Q" encoding. */
int quoted_printable_q_decode(const unsigned char *src, size_t src_size,
			      buffer_t *dest);

#endif
