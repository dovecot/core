/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "charset-utf8.h"

#ifdef HAVE_ICONV

#include <iconv.h>
#include <ctype.h>

struct charset_translation {
	iconv_t cd;
	normalizer_func_t *normalizer;
};

int charset_to_utf8_begin(const char *charset, normalizer_func_t *normalizer,
			  struct charset_translation **t_r)
{
	struct charset_translation *t;
	iconv_t cd;

	if (charset_is_utf8(charset))
		cd = (iconv_t)-1;
	else {
		cd = iconv_open("UTF-8", charset);
		if (cd == (iconv_t)-1)
			return -1;
	}

	t = i_new(struct charset_translation, 1);
	t->cd = cd;
	t->normalizer = normalizer;
	*t_r = t;
	return 0;
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

static int
charset_append_utf8(struct charset_translation *t,
		    const void *src, size_t src_size, buffer_t *dest)
{
	if (t->normalizer != NULL)
		return t->normalizer(src, src_size, dest);
	else if (!uni_utf8_get_valid_data(src, src_size, dest))
		return -1;
	else {
		buffer_append(dest, src, src_size);
		return 0;
	}
}

static bool
charset_to_utf8_try(struct charset_translation *t,
		    const unsigned char *src, size_t *src_size, buffer_t *dest,
		    enum charset_result *result)
{
	ICONV_CONST char *ic_srcbuf;
	char tmpbuf[8192], *ic_destbuf;
	size_t srcleft, destleft;
	bool ret = TRUE;

	if (t->cd == (iconv_t)-1) {
		/* input is already supposed to be UTF-8 */
		if (charset_append_utf8(t, src, *src_size, dest) < 0)
			*result = CHARSET_RET_INVALID_INPUT;
		else
			*result = CHARSET_RET_OK;
		return TRUE;
	}
	destleft = sizeof(tmpbuf);
	ic_destbuf = tmpbuf;
	srcleft = *src_size;
	ic_srcbuf = (ICONV_CONST char *) src;

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
		ret = FALSE;
	}
	*src_size -= srcleft;

	/* we just converted data to UTF-8. it shouldn't be invalid, but
	   Solaris iconv appears to pass invalid data through sometimes
	   (e.g. 8 bit characters with UTF-7) */
	if (charset_append_utf8(t, tmpbuf, sizeof(tmpbuf) - destleft,
				dest) < 0)
		*result = CHARSET_RET_INVALID_INPUT;
	return ret;
}

enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	enum charset_result result;
	size_t pos, size;
	size_t prev_invalid_pos = (size_t)-1;
	bool ret;

	for (pos = 0;;) {
		size = *src_size - pos;
		ret = charset_to_utf8_try(t, src + pos, &size, dest, &result);
		pos += size;

		if (ret)
			break;

		if (result == CHARSET_RET_INVALID_INPUT) {
			if (prev_invalid_pos != dest->used) {
				uni_ucs4_to_utf8_c(UNICODE_REPLACEMENT_CHAR,
						   dest);
				prev_invalid_pos = dest->used;
			}
			pos++;
		}
	}

	if (prev_invalid_pos != (size_t)-1)
		result = CHARSET_RET_INVALID_INPUT;

	*src_size = pos;
	return result;
}

#endif
