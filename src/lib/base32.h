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

/* Translates binary data into Crockford's base32 alphabet
   (https://www.crockford.com/base32.html) using upper case letters and no
   padding. The bytes are packed most significant bit first, 5 bits per
   character, as in RFC 4648, and the last character is filled up with zero
   bits. Crockford's page encodes a number instead, and an encoder of
   numbers (such as for ULIDs) can give different output for the same
   bytes. The src must not point to dest buffer. */
void base32crockford_encode(const void *src, size_t src_size,
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

/* Translates Crockford's base32 data into binary and appends it to dest
   buffer. Letters are case-insensitive, O is read as 0 and I and L as 1.
   Hyphens are ignored. Returns 0 if all ok, -1 if data is invalid: an
   invalid character, a length no encoder produces, or non-zero bits after
   the last full byte. On failure, dest may contain partially decoded
   data. The src must not point to dest buffer, since the decoded bytes are
   appended to dest while src is still being read. Unlike base32_decode(),
   this does not support decoding a stream in parts: there is no padding
   that would mark the end of the data. Crockford's optional check symbols
   are not supported. */
int base32crockford_decode(const void *src, size_t src_size, buffer_t *dest);

/* Decode given string to a buffer allocated from data stack. */
buffer_t *t_base32_decode_str(const char *str);
buffer_t *t_base32hex_decode_str(const char *str);

/* Returns TRUE if c is a valid base32 encoding character (excluding '=') */
bool base32_is_valid_char(char c);
bool base32hex_is_valid_char(char c);
/* Returns TRUE if c is a valid Crockford's base32 encoding character,
   including the aliases accepted by base32crockford_decode(). Hyphens are
   accepted by base32crockford_decode() but not by this function. */
bool base32crockford_is_valid_char(char c);

/* max. buffer size required for base32_encode()/base32hex_encode()/
   base32crockford_encode() */
#define MAX_BASE32_ENCODED_SIZE(size) \
	((size) / 5 * 8 + 8)
/* max. buffer size required for base32_decode()/base32hex_decode()/
   base32crockford_decode() */
#define MAX_BASE32_DECODED_SIZE(size) \
	((size) / 8 * 5 + 5)

#endif
