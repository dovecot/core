#ifndef __BASE64_H
#define __BASE64_H

/* Translates binary data into base64. Allocates memory from data stack. */
const char *base64_encode(const unsigned char *data, size_t size);

/* Translates base64 data into binary. dest must be large enough, and may be
   same as src. Returns size of the binary data, or -1 if error occured.
   Any CR, LF characters are ignored, as well as whitespace at beginning or
   end of line.

   This function may be called multiple times for parsing same base64 stream.
   The *size is updated at return to contain the amount of data actually
   parsed - the rest of the data should be passed again to this function. */
ssize_t base64_decode(const char *src, size_t *size, unsigned char *dest);

/* max. buffer size required for base64_decode(), not including trailing \0 */
#define MAX_BASE64_DECODED_SIZE(size) \
	((size) / 4 * 3 + 3)

#endif
