#ifndef BASE64_H
#define BASE64_H

/*
 * Common Base64
 */

/* max. buffer size required for base64_encode() */
#define MAX_BASE64_ENCODED_SIZE(size) \
	((((size) + 2) / 3) * 4)
/* max. buffer size required for base64_decode() */
#define MAX_BASE64_DECODED_SIZE(size) \
	(((size) + 3) / 4 * 3)

struct base64_scheme {
	const char encmap[64];
	const unsigned char decmap[256];
};

/*
 * Low-level Base64 encoder
 */

enum base64_encode_flags {
	/* Use CRLF instead of the default LF as line ending. */
	BASE64_ENCODE_FLAG_CRLF                 = BIT(0),
	/* Encode no padding at the end of the data. */
	BASE64_ENCODE_FLAG_NO_PADDING           = BIT(1),
};

struct base64_encoder {
	const struct base64_scheme *b64;
	enum base64_encode_flags flags;
	size_t max_line_len;

	/* state */
	unsigned int sub_pos;
	unsigned char buf;
	size_t cur_line_len;

	unsigned char w_buf[4];
	unsigned int w_buf_len;

	bool finished:1;
};

/* Returns TRUE when base64_encode_finish() was called on this encoder. */
static inline bool
base64_encode_is_finished(struct base64_encoder *enc)
{
	return enc->finished;
}

/* Initialize the Base64 encoder. The b64 parameter is the definition of the
   particular Base64 encoding scheme that is used.
 */
static inline void
base64_encode_init(struct base64_encoder *enc,
		   const struct base64_scheme *b64,
		   enum base64_encode_flags flags,
		   size_t max_line_len)
{
	i_zero(enc);
	enc->b64 = b64;
	enc->flags = flags;
	enc->max_line_len = (max_line_len == 0 ? SIZE_MAX : max_line_len);
}

/* Reset the Base64 encoder to its initial state. */
static inline void
base64_encode_reset(struct base64_encoder *enc)
{
	const struct base64_scheme *b64 = enc->b64;
	enum base64_encode_flags flags = enc->flags;
	size_t max_line_len = enc->max_line_len;

	base64_encode_init(enc, b64, flags, max_line_len);
}

/* Translate the size of the full encoder input to the size of the encoder
   output.
 */
off_t base64_get_full_encoded_size(struct base64_encoder *enc, off_t src_size);
/* Translate the size of the next input to the size of the output once encoded.
   This yields the amount of data appended to the dest buffer by
   base64_encode_more() with the indicated src_size. */
size_t base64_encode_get_size(struct base64_encoder *enc, size_t src_size);

/* Translates binary data into some form of Base64. The src must not point to
   dest buffer. Returns TRUE when all the provided data is encoded. Returns
   FALSE when the space in the provided buffer is insufficient. The return value
   may be ignored. If src_pos_r is non-NULL, it's updated to first
   non-translated character in src.
 */
bool ATTR_NOWARN_UNUSED_RESULT
base64_encode_more(struct base64_encoder *enc, const void *src, size_t src_size,
		   size_t *src_pos_r, buffer_t *dest) ATTR_NULL(4);

/* Finishes Base64 encoding. Returns TRUE when all the provided data is encoded.
   Returns FALSE when the space in the provided buffer is insufficient. The
   return value may be ignored.
 */
bool ATTR_NOWARN_UNUSED_RESULT
base64_encode_finish(struct base64_encoder *enc, buffer_t *dest) ATTR_NULL(2);

/*
 * Low-level Base64 decoder
 */

enum base64_decode_flags {
	/* Decode input until a boundary is reached. This boundary is a
	   non-Base64 input sequence that would normally trigger a decode error;
	   e.g., Base64 data followed by a ':'. With this flag, it is possible
	   to decode such a Base64 prefix. The base64_decode_finish() function
	   will still check that the Base64 data ends properly (padding). */
	BASE64_DECODE_FLAG_EXPECT_BOUNDARY = BIT(0),
	/* Prohibit whitespace in the input. */
	BASE64_DECODE_FLAG_NO_WHITESPACE   = BIT(1),
	/* Require absence of padding at the end of the input. */
	BASE64_DECODE_FLAG_NO_PADDING      = BIT(2),
	/* Ignore padding at the end of the input. This flag is ignored when
	   BASE64_DECODE_FLAG_NO_PADDING is also set. If both of these flags are
	   absent, padding is required (the default). */
	BASE64_DECODE_FLAG_IGNORE_PADDING  = BIT(3),
};

struct base64_decoder {
	const struct base64_scheme *b64;
	enum base64_decode_flags flags;

	/* state */
	unsigned int sub_pos;
	unsigned char buf;

	bool seen_padding:1;
	bool seen_end:1;
	bool seen_boundary:1;
	bool finished:1;
	bool failed:1;
};

/* Returns TRUE when base64_decode_finish() was called on this decoder. */
static inline bool
base64_decode_is_finished(struct base64_decoder *dec)
{
	return dec->finished;
}

/* Initialize the Base64 decoder. The b64 parameter is the definition of the
   particular Base64 encoding scheme that is expected.
 */
static inline void
base64_decode_init(struct base64_decoder *dec,
		   const struct base64_scheme *b64,
		   enum base64_decode_flags flags)
{
	i_zero(dec);
	dec->b64 = b64;
	dec->flags = flags;
}

/* Reset the Base64 decoder to its initial state. */
static inline void
base64_decode_reset(struct base64_decoder *dec)
{
	const struct base64_scheme *b64 = dec->b64;
	enum base64_decode_flags flags = dec->flags;

	base64_decode_init(dec, b64, flags);
}

/* Translates some form of Base64 data into binary and appends it to dest
   buffer. dest may point to same buffer as src. Returns 1 if all ok, 0 if end
   of base64 data found, -1 if data is invalid.

   By default, any CR, LF characters are ignored, as well as any whitespace.
   This can be overridden using the BASE64_DECODE_FLAG_NO_WHITESPACE flag.

   If src_pos is non-NULL, it's updated to first non-translated character in
   src.
 */
int base64_decode_more(struct base64_decoder *dec,
		       const void *src, size_t src_size, size_t *src_pos_r,
		       buffer_t *dest) ATTR_NULL(4);
/* Finishes Base64 decoding. This function checks whether the encoded data ends
   in the proper padding. Returns 0 if all ok, and -1 if data is invalid.
 */
int base64_decode_finish(struct base64_decoder *dec);

/*
 * Generic Base64 API
 */

/* Translates binary data into some variant of Base64. The src must not point to
   dest buffer.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is used. See below for specific functions.
 */
static inline void
base64_scheme_encode(const struct base64_scheme *b64,
		     const void *src, size_t src_size, buffer_t *dest)
{
	struct base64_encoder enc;

	base64_encode_init(&enc, b64, 0, 0);
	base64_encode_more(&enc, src, src_size, NULL, dest);
	base64_encode_finish(&enc, dest);
}

/* Translates some variant of Base64 data into binary and appends it to dest
   buffer. dest may point to same buffer as src. Returns 1 if all ok, 0 if end
   of Base64 data found, -1 if data is invalid.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is expected. See below for specific functions.

   Any CR, LF characters are ignored, as well as whitespace at beginning or
   end of line.
 */
int base64_scheme_decode(const struct base64_scheme *b64,
			 enum base64_decode_flags flags,
			 const void *src, size_t src_size, buffer_t *dest);

/* Decode given data to a buffer allocated from data stack.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is expected. See below for specific functions.
 */
buffer_t *t_base64_scheme_decode(const struct base64_scheme *b64,
				 enum base64_decode_flags flags,
				 const void *src, size_t src_size);
/* Decode given string to a buffer allocated from data stack.

   The b64 parameter is the definition of the particular Base 64 encoding scheme
   that is expected. See below for specific functions.
 */
static inline buffer_t *
t_base64_scheme_decode_str(const struct base64_scheme *b64,
			   enum base64_decode_flags flags, const char *str)
{
	return t_base64_scheme_decode(b64, flags, str, strlen(str));
}

/* Returns TRUE if c is a valid encoding character (excluding '=') for the
   provided base64 mapping table */
static inline bool
base64_scheme_is_valid_char(const struct base64_scheme *b64, char c)
{
	return b64->decmap[(uint8_t)c] != 0xff;
}

/*
 * "base64" encoding scheme (RFC 4648, Section 4)
 */

extern struct base64_scheme base64_scheme;

/* Translates binary data into base64. See base64_scheme_encode(). */
static inline void
base64_encode(const void *src, size_t src_size, buffer_t *dest)
{
	base64_scheme_encode(&base64_scheme, src, src_size, dest);
}

/* Translates base64 data into binary and appends it to dest buffer. See
   base64_scheme_decode().

   The src_pos_r parameter is deprecated and MUST be NULL.
 */
static inline int
base64_decode(const void *src, size_t src_size, size_t *src_pos_r ATTR_UNUSED,
	      buffer_t *dest) ATTR_NULL(3)
{
	// NOTE: src_pos_r is deprecated here; to be removed in v2.4 */
	i_assert(src_pos_r == NULL);

	return base64_scheme_decode(&base64_scheme, 0, src, src_size, dest);
}

/* Decode given data to a buffer allocated from data stack. */
static inline buffer_t *
t_base64_decode(enum base64_decode_flags flags,
		const void *src, size_t src_size)
{
	return t_base64_scheme_decode(&base64_scheme, flags, src, src_size);
}

/* Decode given string to a buffer allocated from data stack. */
static inline buffer_t *t_base64_decode_str(const char *str)
{
	return t_base64_scheme_decode_str(&base64_scheme, 0, str);
}

/* Returns TRUE if c is a valid base64 encoding character (excluding '=') */
static inline bool base64_is_valid_char(char c)
{
	return base64_scheme_is_valid_char(&base64_scheme, c);
}

/*
 * "base64url" encoding scheme (RFC 4648, Section 5)
 */

extern struct base64_scheme base64url_scheme;

/* Translates binary data into base64url. See base64_scheme_encode(). */
static inline void
base64url_encode(const void *src, size_t src_size, buffer_t *dest)
{
	base64_scheme_encode(&base64url_scheme, src, src_size, dest);
}

/* Translates base64url data into binary and appends it to dest buffer. See
   base64_scheme_decode(). */
static inline int
base64url_decode(enum base64_decode_flags flags,
		 const void *src, size_t src_size, buffer_t *dest)
{
	return base64_scheme_decode(&base64url_scheme, flags,
				    src, src_size, dest);
}

/* Decode given data to a buffer allocated from data stack. */
static inline buffer_t *
t_base64url_decode(enum base64_decode_flags flags,
		   const void *src, size_t src_size)
{
	return t_base64_scheme_decode(&base64url_scheme, flags, src, src_size);
}

/* Decode given string to a buffer allocated from data stack. */
static inline buffer_t *
t_base64url_decode_str(enum base64_decode_flags flags, const char *str)
{
	return t_base64_scheme_decode_str(&base64url_scheme, flags, str);
}

/* Returns TRUE if c is a valid base64url encoding character (excluding '=') */
static inline bool base64url_is_valid_char(char c)
{
	return base64_scheme_is_valid_char(&base64url_scheme, c);
}

#endif
