#ifndef UNICHAR_H
#define UNICHAR_H

/* Character used to replace invalid input. */
#define UNICODE_REPLACEMENT_CHAR 0xfffd

/* Characters >= base require surrogates */
#define UTF16_SURROGATE_BASE 0x10000

#define UTF16_SURROGATE_SHIFT 10
#define UTF16_SURROGATE_MASK 0x03ff
#define UTF16_SURROGATE_HIGH_FIRST 0xd800
#define UTF16_SURROGATE_HIGH_LAST 0xdbff
#define UTF16_SURROGATE_HIGH_MAX 0xdfff
#define UTF16_SURROGATE_LOW_FIRST 0xdc00
#define UTF16_SURROGATE_LOW_LAST 0xdfff

#define UTF16_SURROGATE_HIGH(chr) \
	(UTF16_SURROGATE_HIGH_FIRST + \
	 (((chr) - UTF16_SURROGATE_BASE) >> UTF16_SURROGATE_SHIFT))
#define UTF16_SURROGATE_LOW(chr) \
	(UTF16_SURROGATE_LOW_FIRST + \
	 (((chr) - UTF16_SURROGATE_BASE) & UTF16_SURROGATE_MASK))

#define UTF8_REPLACEMENT_CHAR_LEN 3

typedef uint32_t unichar_t;
ARRAY_DEFINE_TYPE(unichars, unichar_t);

extern const unsigned char utf8_replacement_char[UTF8_REPLACEMENT_CHAR_LEN];
extern const uint8_t *const uni_utf8_non1_bytes;

/* Returns number of characters in a NUL-terminated unicode string */
unsigned int uni_strlen(const unichar_t *str) ATTR_PURE;
/* Translates UTF-8 input to UCS-4 output. Returns 0 if ok, -1 if input was
   invalid */
int uni_utf8_to_ucs4(const char *input, ARRAY_TYPE(unichars) *output);
int uni_utf8_to_ucs4_n(const unsigned char *input, size_t size,
		       ARRAY_TYPE(unichars) *output);
/* Translates UCS-4 input to UTF-8 output. */
void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output);
void uni_ucs4_to_utf8_c(unichar_t chr, buffer_t *output);

/* Returns 1 if *chr_r is set, 0 for incomplete trailing character,
   -1 for invalid input. */
int uni_utf8_get_char(const char *input, unichar_t *chr_r);
int uni_utf8_get_char_n(const void *input, size_t max_len, unichar_t *chr_r);
/* Returns UTF-8 string length with maximum input size. */
unsigned int uni_utf8_strlen_n(const void *input, size_t size) ATTR_PURE;

/* Returns the number of bytes belonging to this UTF-8 character. The given
   parameter is the first byte of the UTF-8 sequence. Invalid input is
   returned with length 1. */
static inline unsigned int ATTR_CONST
uni_utf8_char_bytes(char chr)
{
	/* 0x00 .. 0x7f are ASCII. 0x80 .. 0xC1 are invalid. */
	if ((uint8_t)chr < (192 + 2))
		return 1;
	return uni_utf8_non1_bytes[(uint8_t)chr - (192 + 2)];
}

/* Return given character in titlecase. */
unichar_t uni_ucs4_to_titlecase(unichar_t chr) ATTR_CONST;

/* Convert UTF-8 input to titlecase and decompose the titlecase characters to
   output buffer. Returns 0 if ok, -1 if input was invalid. This generates
   output that's compatible with i;unicode-casemap comparator. Invalid input
   is replaced with unicode replacement character (0xfffd). */
int uni_utf8_to_decomposed_titlecase(const void *input, size_t max_len,
				     buffer_t *output);

/* If input contains only valid UTF-8 characters, return TRUE without updating
   buf. If input contains invalid UTF-8 characters, replace them with unicode
   replacement character (0xfffd), write the output to buf and return FALSE. */
bool uni_utf8_get_valid_data(const unsigned char *input, size_t size,
			     buffer_t *buf);
/* Returns TRUE if string is valid UTF-8 input. */
bool uni_utf8_str_is_valid(const char *str);
/* Returns TRUE if data contains only valid UTF-8 input. */
bool uni_utf8_data_is_valid(const unsigned char *data, size_t size);

#endif
