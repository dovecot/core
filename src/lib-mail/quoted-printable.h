#ifndef __QUOTED_PRINTABLE_H
#define __QUOTED_PRINTABLE_H

/* Translates quoted printable data into binary. dest must be at least the
   size of src, and may be same as src. Returns size of the binary data.
   Decoding errors are ignored.

   This function may be called multiple times for parsing same stream.
   The *size is updated at return to contain the amount of data actually
   parsed - the rest of the data should be passed again to this function. */
size_t quoted_printable_decode(const unsigned char *src, size_t *size,
			       unsigned char *dest);

#endif
