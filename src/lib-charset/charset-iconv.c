/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "charset-utf8.h"

#ifdef HAVE_ICONV_H

#include <iconv.h>
#include <ctype.h>

#ifdef __sun__
#  define ICONV_CONST const
#else
#  define ICONV_CONST
#endif

struct _CharsetTranslation {
	iconv_t cd;
	int ascii;
};

CharsetTranslation *charset_to_utf8_begin(const char *charset,
					  int *unknown_charset)
{
	CharsetTranslation *t;
	iconv_t cd;
	int ascii;

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	if (strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0) {
		cd = NULL;
		ascii = TRUE;
	} else if (strcasecmp(charset, "UTF-8") == 0 ||
		   strcasecmp(charset, "UTF8") == 0) {
		cd = NULL;
		ascii = FALSE;
	} else {
		ascii = FALSE;
		cd = iconv_open("UTF-8", charset);
		if (cd == (iconv_t)-1) {
			if (unknown_charset != NULL)
				*unknown_charset = TRUE;
			return NULL;
		}
	}

	t = i_new(CharsetTranslation, 1);
	t->cd = cd;
	t->ascii = ascii;
	return t;
}

void charset_to_utf8_end(CharsetTranslation *t)
{
	if (t->cd != NULL)
		iconv_close(t->cd);
	i_free(t);
}

void charset_to_utf8_reset(CharsetTranslation *t)
{
	if (t->cd != NULL)
		(void)iconv(t->cd, NULL, NULL, NULL, NULL);
}

int charset_to_ucase_utf8(CharsetTranslation *t,
			  const unsigned char **inbuf, size_t *insize,
			  unsigned char *outbuf, size_t *outsize)
{
	ICONV_CONST char *ic_inbuf;
	char *ic_outbuf;
	size_t outleft, max_size, i;

	if (t->cd == NULL) {
		/* no translation needed - just copy it to outbuf uppercased */
		max_size = I_MIN(*insize, *outsize);
		for (i = 0; i < max_size; i++)
			outbuf[i] = i_toupper((*inbuf)[i]); /* FIXME: utf8 */
		*insize = 0;
		*outsize = max_size;
		return TRUE;
	}

	ic_inbuf = (ICONV_CONST char *) *inbuf;
	ic_outbuf = (char *) outbuf;
	outleft = *outsize;

	if (iconv(t->cd, &ic_inbuf, insize,
		  &ic_outbuf, &outleft) == (size_t)-1) {
		if (errno != E2BIG && errno != EINVAL) {
			/* should be EILSEQ - invalid input */
			return FALSE;
		}
	}

	*inbuf = (const unsigned char *) ic_inbuf;
	*outsize -= outleft;

	max_size = *outsize;
	for (i = 0; i < max_size; i++)
		outbuf[i] = i_toupper(outbuf[i]); /* FIXME: utf8 */

	return TRUE;
}

const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const unsigned char *buf, size_t *size)
{
	iconv_t cd;
	ICONV_CONST char *inbuf;
	char *outbuf, *outpos;
	size_t inleft, outleft, outsize, pos;

	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0)
		return str_ucase(t_strdup_noconst(buf));

	cd = iconv_open("UTF-8", charset);
	if (cd == (iconv_t)-1) {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	inbuf = (ICONV_CONST char *) buf;
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

	str_ucase(outbuf); /* FIXME: utf8 */

	iconv_close(cd);
	return outbuf;
}

#endif
