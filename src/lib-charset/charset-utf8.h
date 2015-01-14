#ifndef CHARSET_UTF8_H
#define CHARSET_UTF8_H

#include "unichar.h"

/* Max number of bytes that iconv can require for a single character.
   UTF-8 takes max 6 bytes per character. Not sure about others, but I'd think
   10 is more than enough for everyone.. */
#define CHARSET_MAX_PENDING_BUF_SIZE 10

struct charset_translation;

enum charset_result {
	CHARSET_RET_OK = 1,
	CHARSET_RET_INCOMPLETE_INPUT = -1,
	CHARSET_RET_INVALID_INPUT = -2
};

/* Begin translation to UTF-8. Returns -1 if charset is unknown. */
int charset_to_utf8_begin(const char *charset, normalizer_func_t *normalizer,
			  struct charset_translation **t_r)
	ATTR_NULL(2);
/* Translate UTF-8 to UTF-8 while validating the input. */
struct charset_translation *
charset_utf8_to_utf8_begin(normalizer_func_t *normalizer);
void charset_to_utf8_end(struct charset_translation **t);
void charset_to_utf8_reset(struct charset_translation *t);

/* Returns TRUE if charset is UTF-8 or ASCII */
bool charset_is_utf8(const char *charset) ATTR_PURE;

/* Translate src to UTF-8. src_size is updated to contain the number of
   characters actually translated from src. The src_size should never shrink
   more than CHARSET_MAX_PENDING_BUF_SIZE bytes.

   If src contains invalid input, UNICODE_REPLACEMENT_CHAR is placed in such
   positions and the invalid input is skipped over. Return value is also
   CHARSET_RET_INCOMPLETE_INPUT in that case. */
enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest);

/* Translate a single string to UTF8. */
int charset_to_utf8_str(const char *charset, normalizer_func_t *normalizer,
			const char *input, string_t *output,
			enum charset_result *result_r) ATTR_NULL(2);

/* INTERNAL: */
enum charset_result
charset_utf8_to_utf8(normalizer_func_t *normalizer,
		     const unsigned char *src, size_t *src_size, buffer_t *dest);

#endif
