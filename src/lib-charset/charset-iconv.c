/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"

#ifdef HAVE_ICONV_H

#include <iconv.h>

const char *charset_to_ucase_utf8(const unsigned char *data, size_t *size,
				  const char *charset, int *unknown_charset)
{
	iconv_t cd;
	char *inbuf, *outbuf, *outpos;
	size_t inleft, outleft, outsize, pos;

	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0)
		return str_ucase(t_strdup_noconst(data));

	cd = iconv_open("UTF8", charset);
	if (cd == (iconv_t)-1) {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	inbuf = (char *) data;
	inleft = *size;

	outsize = outleft = *size * 2;
	outbuf = outpos = t_buffer_get(outsize + 1);

	while (iconv(cd, &inbuf, &inleft, &outpos, &outleft) == (size_t)-1) {
		if (errno != E2BIG) {
			/* invalid data */
			iconv_close(cd);
			return NULL;
		}

		/* output buffer too small, grow it */
		pos = outsize - outleft;
		outsize *= 2;
		outleft = outsize - pos;

		outbuf = t_buffer_reget(outbuf, outsize + 1);
		outpos = outbuf + pos;
	}

	*size = (size_t) (outpos - outbuf);
	*outpos++ = '\0';
	t_buffer_alloc(*size + 1);

	/* FIXME: this works only for ASCII */
	str_ucase(outbuf);

	iconv_close(cd);
	return outbuf;
}

#endif
