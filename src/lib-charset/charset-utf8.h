#ifndef __CHARSET_UTF8_H
#define __CHARSET_UTF8_H

const char *charset_to_ucase_utf8(const unsigned char *data, size_t *size,
				  const char *charset, int *unknown_charset);

#endif
