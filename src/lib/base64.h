#ifndef BASE64_H
#define BASE64_H

/* max. buffer size required for base64_encode() */
#define MAX_BASE64_ENCODED_SIZE(size) \
	((((size) + 2) / 3) * 4)
/* max. buffer size required for base64_decode() */
#define MAX_BASE64_DECODED_SIZE(size) \
	(((size) + 3) / 4 * 3)

/* Translates binary data into base64. The src must not point to dest buffer. */
void base64_encode(const void *src, size_t src_size, buffer_t *dest);

/* Translates base64 data into binary and appends it to dest buffer. dest may
   point to same buffer as src. Returns 1 if all ok, 0 if end of base64 data
   found, -1 if data is invalid.

   Any CR, LF characters are ignored, as well as whitespace at beginning or
   end of line.

   This function may be called multiple times for parsing the same stream.
   If src_pos is non-NULL, it's updated to first non-translated character in
   src. */
int base64_decode(const void *src, size_t src_size,
		  size_t *src_pos_r, buffer_t *dest) ATTR_NULL(3);

/* Decode given string to a buffer allocated from data stack. */
buffer_t *t_base64_decode_str(const char *str);

/* Returns TRUE if c is a valid base64 encoding character (excluding '=') */
bool base64_is_valid_char(char c);

#endif
