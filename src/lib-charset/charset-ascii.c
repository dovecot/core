/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"

#ifndef HAVE_ICONV_H

const char *charset_to_ucase_utf8(const unsigned char *data,
				  size_t *size __attr_unused__,
				  const char *charset, int *unknown_charset)
{
	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0)
		return str_ucase(t_strdup_noconst(data));

	if (unknown_charset != NULL)
		*unknown_charset = TRUE;
	return NULL;
}

#endif
