#ifndef __CHARSET_UTF8_H
#define __CHARSET_UTF8_H

typedef struct _CharsetTranslation CharsetTranslation;

/* Begin translation to UTF-8. */
CharsetTranslation *charset_to_utf8_begin(const char *charset,
					  int *unknown_charset);

void charset_to_utf8_end(CharsetTranslation *t);

void charset_to_utf8_reset(CharsetTranslation *t);

/* Convert inbuf to UTF-8. inbuf and inbuf_size is updated to specify beginning
   of data that was not written to outbuf, either because of inbuf ended with
   incomplete character sequence or because the outbuf got full. Returns TRUE
   if no conversion errors were detected. */
int charset_to_ucase_utf8(CharsetTranslation *t,
			  const unsigned char **inbuf, size_t *insize,
			  unsigned char *outbuf, size_t *outsize);

/* Simple wrapper for above functions. size is updated to strlen() of
   returned UTF-8 string. */
const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const unsigned char *buf, size_t *size);

#endif
