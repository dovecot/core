/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"

#ifdef HAVE_ICONV

#include <iconv.h>
#include <ctype.h>

struct charset_translation {
	iconv_t cd;
	unsigned int ucase:1;
};

struct charset_translation *
charset_to_utf8_begin(const char *charset, bool ucase, bool *unknown_charset_r)
{
	struct charset_translation *t;
	iconv_t cd;

	if (unknown_charset_r != NULL)
		*unknown_charset_r = FALSE;

	if (charset_is_utf8(charset))
		cd = (iconv_t)-1;
	else {
		cd = iconv_open("UTF-8", charset);
		if (cd == (iconv_t)-1) {
			if (unknown_charset_r != NULL)
				*unknown_charset_r = TRUE;
			return NULL;
		}
	}

	t = i_new(struct charset_translation, 1);
	t->cd = cd;
	t->ucase = ucase;
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

static bool
charset_to_utf8_try(struct charset_translation *t,
		    const unsigned char *src, size_t *src_size, buffer_t *dest,
		    enum charset_result *result)
{
	ICONV_CONST char *ic_srcbuf;
	char *ic_destbuf;
	size_t srcleft, destpos, destleft, size;
	bool ret = TRUE;

	destpos = dest->used;
	if (t->cd == (iconv_t)-1) {
		/* no translation needed - just copy it to outbuf uppercased */
		if (t->ucase)
			charset_utf8_ucase_write(dest, destpos, src, *src_size);
		else
			buffer_append(dest, src, *src_size);

		*result = CHARSET_RET_OK;
		return TRUE;
	}
	destleft = buffer_get_size(dest) - destpos;
	if (destleft < *src_size) {
		/* The buffer is most likely too small to hold the output,
		   so increase it at least to the input size. */
		destleft = *src_size;
	}

	size = destleft;
	srcleft = *src_size;
	ic_srcbuf = (ICONV_CONST char *) src;
	ic_destbuf = buffer_append_space_unsafe(dest, destleft);

	if (iconv(t->cd, &ic_srcbuf, &srcleft,
		  &ic_destbuf, &destleft) != (size_t)-1)
		*result = CHARSET_RET_OK;
	else if (errno == E2BIG) {
		/* set result just to avoid compiler warning */
		*result = CHARSET_RET_INCOMPLETE_INPUT;
		ret = FALSE;
	} else if (errno == EINVAL)
		*result = CHARSET_RET_INCOMPLETE_INPUT;
	else {
		/* should be EILSEQ */
		*result = CHARSET_RET_INVALID_INPUT;
		return TRUE;
	}
	size -= destleft;

	/* give back the memory we didn't use */
	buffer_set_used_size(dest, dest->used - destleft);

	*src_size -= srcleft;
	if (t->ucase) {
		charset_utf8_ucase_write(dest, destpos,
					 (unsigned char *)ic_destbuf - size,
					 size);
	}
	return ret;
}

enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	enum charset_result result;
	size_t pos, used, size;
	bool ret;

	for (pos = 0;;) {
		size = *src_size - pos;
		ret = charset_to_utf8_try(t, src + pos, &size, dest, &result);
		pos += size;

		if (ret) {
			*src_size = pos;
			return result;
		}

		/* force buffer to grow */
		used = dest->used;
		size = buffer_get_size(dest) - used + 1;
		(void)buffer_append_space_unsafe(dest, size);
		buffer_set_used_size(dest, used);
	}
}

#endif
