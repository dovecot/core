/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
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

static void str_ucase_utf8(const unsigned char *src, size_t src_size,
			   Buffer *dest, size_t destpos)
{
	char *destbuf;
	size_t i;

	destbuf = buffer_get_space(dest, destpos, src_size);
	for (i = 0; i < src_size; i++)
		destbuf[i] = i_toupper(src[i]); /* FIXME: utf8 */
}

CharsetResult
charset_to_ucase_utf8(CharsetTranslation *t,
		      const Buffer *src, size_t *src_pos, Buffer *dest)
{
	ICONV_CONST char *ic_srcbuf;
	char *ic_destbuf;
	size_t srcleft, destpos, destleft, size;
        CharsetResult ret;

	destpos = buffer_get_used_size(dest);
	destleft = buffer_get_size(dest) - destpos;

	if (t->cd == NULL) {
		/* no translation needed - just copy it to outbuf uppercased */
		size = buffer_get_used_size(src);
		if (size > destleft)
			size = destleft;
		str_ucase_utf8(buffer_get_data(src, NULL), size, dest, destpos);
		if (src_pos != NULL)
			*src_pos = size;
		return CHARSET_RET_OK;
	}

	size = destleft;
	ic_srcbuf = (ICONV_CONST char *) buffer_get_data(src, &srcleft);
	ic_destbuf = buffer_append_space(dest, destleft);

	if (iconv(t->cd, &ic_srcbuf, &srcleft,
		  &ic_destbuf, &destleft) != (size_t)-1)
		ret = CHARSET_RET_OK;
	else if (errno == E2BIG)
		ret = CHARSET_RET_OUTPUT_FULL;
	else if (errno == EINVAL)
		ret = CHARSET_RET_INCOMPLETE_INPUT;
	else {
		/* should be EILSEQ */
		return CHARSET_RET_INVALID_INPUT;
	}
	size -= destleft;

	/* give back the memory we didn't use */
	buffer_set_used_size(dest, buffer_get_used_size(dest) - destleft);

	if (src_pos != NULL)
		*src_pos = buffer_get_used_size(src) - srcleft;

	str_ucase_utf8((unsigned char *) ic_destbuf - size, size,
		       dest, destpos);
	return ret;
}

static const char *alloc_str_ucase_utf8(const Buffer *data, size_t *utf8_size)
{
	const char *buf;
	size_t size;
	Buffer *dest;

	buf = buffer_get_data(data, &size);

	dest = buffer_create_dynamic(data_stack_pool, size, (size_t)-1);
	str_ucase_utf8(buf, size, dest, 0);
	if (utf8_size != NULL)
		*utf8_size = buffer_get_used_size(dest);
	buffer_append_c(dest, '\0');
	return buffer_free_without_data(dest);
}

const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const Buffer *data, size_t *utf8_size)
{
	iconv_t cd;
	ICONV_CONST char *inbuf;
	char *outbuf, *outpos;
	size_t inleft, outleft, outsize, pos;

	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0 ||
	    strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0)
	       return alloc_str_ucase_utf8(data, utf8_size);

	cd = iconv_open("UTF-8", charset);
	if (cd == (iconv_t)-1) {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	inbuf = (ICONV_CONST char *) buffer_get_data(data, &inleft);;

	outsize = outleft = inleft * 2;
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

	if (utf8_size != NULL)
		*utf8_size = (size_t) (outpos - outbuf);
	*outpos++ = '\0';
	t_buffer_alloc((size_t) (outpos - outbuf));

	str_ucase(outbuf); /* FIXME: utf8 */

	iconv_close(cd);
	return outbuf;
}

#endif
