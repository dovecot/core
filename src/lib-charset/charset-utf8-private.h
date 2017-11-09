#ifndef CHARSET_UTF8_PRIVATE_H
#define CHARSET_UTF8_PRIVATE_H

#include "unichar.h"
#include "charset-utf8.h"

struct charset_utf8_vfuncs {
	int (*to_utf8_begin)(const char *charset, normalizer_func_t *normalizer,
			     struct charset_translation **t_r);
	void (*to_utf8_end)(struct charset_translation *t);
	void (*to_utf8_reset)(struct charset_translation *t);

	enum charset_result (*to_utf8)(struct charset_translation *t,
				       const unsigned char *src,
				       size_t *src_size, buffer_t *dest);
};

extern const struct charset_utf8_vfuncs charset_utf8only;
extern const struct charset_utf8_vfuncs charset_iconv;

#endif
