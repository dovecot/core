#ifndef __CHARSET_UTF8_H
#define __CHARSET_UTF8_H

typedef enum {
	CHARSET_RET_OK = 1,
	CHARSET_RET_OUTPUT_FULL = 0,
	CHARSET_RET_INCOMPLETE_INPUT = -1,
	CHARSET_RET_INVALID_INPUT = -2
} CharsetResult;

typedef struct _CharsetTranslation CharsetTranslation;

/* Begin translation to UTF-8. */
CharsetTranslation *charset_to_utf8_begin(const char *charset,
					  int *unknown_charset);

void charset_to_utf8_end(CharsetTranslation *t);

void charset_to_utf8_reset(CharsetTranslation *t);

/* Translate src to UTF-8. If src_size is updated to contain the number of
   characters actually translated from src. */
CharsetResult
charset_to_ucase_utf8(CharsetTranslation *t,
		      const unsigned char *src, size_t *src_size, Buffer *dest);

/* Simple wrappers for above functions. If utf8_size is non-NULL, it's set
   to same as strlen(returned data). */
const char *
charset_to_utf8_string(const char *charset, int *unknown_charset,
		       const unsigned char *data, size_t size,
		       size_t *utf8_size_r);
const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const unsigned char *data, size_t size,
			     size_t *utf8_size_r);

void _charset_utf8_ucase(const unsigned char *src, size_t src_size,
			 Buffer *dest, size_t destpos);
const char *_charset_utf8_ucase_strdup(const unsigned char *data, size_t size,
				       size_t *utf8_size_r);

#endif
