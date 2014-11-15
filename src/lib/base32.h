#ifndef BASE32_H
#define BASE32_H

/* Translates binary data into base32 (RFC 4648, Section 6). The src must not
   point to dest buffer. The pad argument determines whether output is padded
   with '='.
 */
void base32_encode(bool pad, const void *src, size_t src_size,
	buffer_t *dest);

/* Translates binary data into base32hex (RFC 4648, Section 7). The src must
   not point to dest buffer. The pad argument determines whether output is
   padded with '='.
 */
void base32hex_encode(bool pad, const void *src, size_t src_size,
	buffer_t *dest);

/* Translates base32/base32hex data into binary and appends it to dest buffer.
   dest may point to same buffer as src. Returns 1 if all ok, 0 if end of
   base32 data found, -1 if data is invalid.

   Any whitespace characters are ignored.

   This function may be called multiple times for parsing the same stream.
   If src_pos is non-NULL, it's updated to first non-translated character in
   src. */
int base32_decode(const void *src, size_t src_size,
		  size_t *src_pos_r, buffer_t *dest) ATTR_NULL(4);
int base32hex_decode(const void *src, size_t src_size,
		  size_t *src_pos_r, buffer_t *dest) ATTR_NULL(4);

/* Decode given string to a buffer allocated from data stack. */
buffer_t *t_base32_decode_str(const char *str);
buffer_t *t_base32hex_decode_str(const char *str);

/* Returns TRUE if c is a valid base32 encoding character (excluding '=') */
bool base32_is_valid_char(char c);
bool base32hex_is_valid_char(char c);

/* max. buffer size required for base32_encode()/base32hex_encode() */
#define MAX_BASE32_ENCODED_SIZE(size) \
	((size) / 5 * 8 + 8)
/* max. buffer size required for base32_decode()/base32hex_decode() */
#define MAX_BASE32_DECODED_SIZE(size) \
	((size) / 8 * 5 + 5)

#endif
