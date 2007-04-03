/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"

#ifdef HAVE_ICONV

#include <iconv.h>
#include <ctype.h>

struct charset_translation {
	iconv_t cd;
};

struct charset_translation *charset_to_utf8_begin(const char *charset,
						  bool *unknown_charset)
{
	struct charset_translation *t;
	iconv_t cd;

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	if (charset_is_utf8(charset))
		cd = (iconv_t)-1;
	else {
		cd = iconv_open("UTF-8", charset);
		if (cd == (iconv_t)-1) {
			if (unknown_charset != NULL)
				*unknown_charset = TRUE;
			return NULL;
		}
	}

	t = i_new(struct charset_translation, 1);
	t->cd = cd;
	return t;
}

void charset_to_utf8_end(struct charset_translation **_t)
{
	struct charset_translation *t = *_t;

	*_t = NULL;

	if (t->cd != (iconv_t)-1)
		iconv_close(t->cd);
	i_free(t);
}

void charset_to_utf8_reset(struct charset_translation *t)
{
	if (t->cd != (iconv_t)-1)
		(void)iconv(t->cd, NULL, NULL, NULL, NULL);
}

enum charset_result
charset_to_ucase_utf8(struct charset_translation *t,
		      const unsigned char *src, size_t *src_size,
		      buffer_t *dest)
{
	ICONV_CONST char *ic_srcbuf;
	char *ic_destbuf;
	size_t srcleft, destpos, destleft, size;
        enum charset_result ret;

	destpos = buffer_get_used_size(dest);
	destleft = buffer_get_size(dest) - destpos;

	if (t->cd == (iconv_t)-1) {
		/* no translation needed - just copy it to outbuf uppercased */
		if (*src_size > destleft)
			*src_size = destleft;
		_charset_utf8_ucase(src, *src_size, dest, destpos);
		return CHARSET_RET_OK;
	}

	size = destleft;
	srcleft = *src_size;
	ic_srcbuf = (ICONV_CONST char *) src;
	ic_destbuf = buffer_append_space_unsafe(dest, destleft);

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

	*src_size -= srcleft;
	_charset_utf8_ucase((unsigned char *) ic_destbuf - size, size,
			    dest, destpos);
	return ret;
}

enum charset_result
charset_to_ucase_utf8_full(struct charset_translation *t,
			   const unsigned char *src, size_t *src_size,
			   buffer_t *dest)
{
	enum charset_result ret;
	size_t pos, used, size;

	for (pos = 0;;) {
		size = *src_size - pos;
		ret = charset_to_ucase_utf8(t, src + pos, &size, dest);
		pos += size;

		if (ret != CHARSET_RET_OUTPUT_FULL) {
			*src_size = pos;
			return ret;
		}

		/* force buffer to grow */
		used = dest->used;
		size = buffer_get_size(dest) - used + 1;
		(void)buffer_append_space_unsafe(dest, size);
		buffer_set_used_size(dest, used);
	}
}

static const char *
charset_to_utf8_string_int(const char *charset, bool *unknown_charset,
			   const unsigned char *data, size_t size,
			   size_t *utf8_size_r, bool ucase)
{
	iconv_t cd;
	ICONV_CONST char *inbuf;
	char *outbuf, *outpos;
	size_t inleft, outleft, outsize, pos;

	if (charset == NULL || charset_is_utf8(charset)) {
		if (unknown_charset != NULL)
			*unknown_charset = FALSE;

		if (!ucase) {
			if (utf8_size_r != NULL)
				*utf8_size_r = size;
			return t_strndup(data, size);
		}

		return _charset_utf8_ucase_strdup(data, size, utf8_size_r);
	}

	cd = iconv_open("UTF-8", charset);
	if (cd == (iconv_t)-1) {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}

	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	inbuf = (ICONV_CONST char *) data;
	inleft = size;

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

	if (utf8_size_r != NULL)
		*utf8_size_r = (size_t) (outpos - outbuf);
	*outpos++ = '\0';
	t_buffer_alloc((size_t) (outpos - outbuf));

	if (ucase)
		str_ucase(outbuf); /* FIXME: utf8 */

	iconv_close(cd);
	return outbuf;
}

const char *
charset_to_utf8_string(const char *charset, bool *unknown_charset,
		       const unsigned char *data, size_t size,
		       size_t *utf8_size_r)
{
	return charset_to_utf8_string_int(charset, unknown_charset,
					  data, size, utf8_size_r, FALSE);
}

const char *
charset_to_ucase_utf8_string(const char *charset, bool *unknown_charset,
			     const unsigned char *data, size_t size,
			     size_t *utf8_size_r)
{
	return charset_to_utf8_string_int(charset, unknown_charset,
					  data, size, utf8_size_r, TRUE);
}

#endif
