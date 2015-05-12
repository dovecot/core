/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h" /* unicode replacement char */
#include "fts-filter.h"
#include "fts-filter-private.h"
#include "fts-language.h"

#ifdef HAVE_LIBICU

#include <unicode/utrans.h>
#include <unicode/uenum.h>
#include <unicode/ustring.h>
#include <unicode/ucnv.h>
#include <stdlib.h>

struct fts_filter_normalizer_icu {
	struct fts_filter filter;
	pool_t pool;
	const char *transliterator_id;
	UTransliterator *transliterator;
};

/* Helper to create UTF16, which libicu wants as input.

 On input,  if *dst_uchars_r  > 0,  it indicates  the number  of UChar
 sized  units that  should be  allocated  for the  text. However,  the
 function will not  use the number, if  the text will not  fit in that
 amount.

 On return *dst_uchars_r will contain the number of UChar sized units
 allocated for the dst. NOT the number of bytes nor the length of the
 text. */
static void make_uchar(const char *src, UChar **dst, int32_t *dst_uchars_r)
{
	UErrorCode err = U_ZERO_ERROR;
	int32_t len = strlen(src);
	int32_t ustr_len = 0;
	int32_t ustr_len_actual = 0;
	UChar *retp = NULL;
	int32_t alloc_uchars = 0;

	i_assert(dst_uchars_r != NULL);

	/* Check length required for encoded dst. */
	retp = u_strFromUTF8(NULL, 0, &ustr_len, src, len, &err);

	/* When preflighting a successful call returns a buffer overflow
	   error. */
	if (U_BUFFER_OVERFLOW_ERROR != err && U_FAILURE(err)) {
		i_panic("Failed to estimate allocation size with lib ICU"
		        " u_strFromUTF8(): %s",u_errorName(err));
	}
	i_assert(NULL == retp);

	err = U_ZERO_ERROR;
	if (*dst_uchars_r > 0 && *dst_uchars_r > ustr_len)
		alloc_uchars =  *dst_uchars_r;
	else
		alloc_uchars = ustr_len;
	alloc_uchars++; /* room for null bytes(2) */
	*dst = t_malloc(alloc_uchars * sizeof(UChar));
	*dst_uchars_r = alloc_uchars;
	retp = u_strFromUTF8(*dst, alloc_uchars, &ustr_len_actual,
	                     src, len, &err);

	if (U_FAILURE(err))
		i_panic("Lib ICU u_strFromUTF8 failed: %s", u_errorName(err));
	i_assert(retp == *dst);
	i_assert(ustr_len == ustr_len_actual);
}

static void make_utf8(const UChar *src, const char **_dst)
{
	char *dst;
	char *retp = NULL;
	int32_t dsize = 0;
	int32_t dsize_actual = 0;
	int32_t sub_num = 0;
	UErrorCode err = U_ZERO_ERROR;
	int32_t usrc_len = u_strlen(src); /* libicu selects different codepaths
	                                     depending if srclen -1 or not */

	retp = u_strToUTF8WithSub(NULL, 0, &dsize, src, usrc_len,
	                          UNICODE_REPLACEMENT_CHAR, &sub_num, &err);

	/* Preflighting can cause buffer overflow to be reported */
	if (U_BUFFER_OVERFLOW_ERROR != err && U_FAILURE(err)) {
		i_panic("Failed to estimate allocation size with lib ICU"
		        " u_strToUTF8(): %s",u_errorName(err));
	}
	i_assert(0 == sub_num);
	i_assert(NULL == retp);

	dsize++; /* room for '\0' byte */
	dst = t_malloc(dsize);
	err = U_ZERO_ERROR;
	retp = u_strToUTF8WithSub(dst, dsize, &dsize_actual, src, usrc_len,
	                         UNICODE_REPLACEMENT_CHAR, &sub_num, &err);
	if (U_FAILURE(err))
		i_panic("Lib ICU u_strToUTF8WithSub() failed: %s",
		        u_errorName(err));
	if (dsize_actual >= dsize) {
		i_panic("Produced UTF8 string length (%d) does not fit in "
		        "preflighted(%d). Buffer overflow?",
		        dsize_actual, dsize);
	}
	if (0 != sub_num) {
		i_panic("UTF8 string not well formed. "
		        "Substitutions (%d) were made.", sub_num);
	}
	i_assert(retp == dst);
	*_dst = dst;
}

static void fts_filter_normalizer_icu_destroy(struct fts_filter *filter)
{
	struct fts_filter_normalizer_icu *np =
		(struct fts_filter_normalizer_icu *)filter;

	if (np->transliterator != NULL)
		utrans_close(np->transliterator);
	pool_unref(&np->pool);
}

static int
fts_filter_normalizer_icu_create(const struct fts_language *lang ATTR_UNUSED,
				 const char *const *settings,
				 struct fts_filter **filter_r,
				 const char **error_r)
{
	struct fts_filter_normalizer_icu *np;
	pool_t pp;
	unsigned int i;
	const char *id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC";

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i], *value = settings[i+1];

		if (strcmp(key, "id") == 0) {
			id = value;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}

	pp = pool_alloconly_create(MEMPOOL_GROWING"fts_filter_normalizer_icu",
	                           sizeof(struct fts_filter_normalizer_icu));
	np = p_new(pp, struct fts_filter_normalizer_icu, 1);
	np->pool = pp;
	np->filter = *fts_filter_normalizer_icu;
	np->transliterator_id = p_strdup(pp, id);
	*filter_r = &np->filter;
	return 0;
}

static int
fts_filter_normalizer_icu_create_trans(struct fts_filter_normalizer_icu *np,
				       const char **error_r)
{
	UErrorCode err = U_ZERO_ERROR;
	UParseError perr;
	UChar *id_uchar = NULL;
	int32_t id_len_uchar = 0;

	memset(&perr, 0, sizeof(perr));

	make_uchar(np->transliterator_id, &id_uchar, &id_len_uchar);

	np->transliterator = utrans_openU(id_uchar, u_strlen(id_uchar),
					  UTRANS_FORWARD, NULL, 0, &perr, &err);
	if (U_FAILURE(err)) {
		string_t *str = t_str_new(128);

		str_printfa(str, "Failed to open transliterator for id '%s': %s",
			    np->transliterator_id, u_errorName(err));
		if (perr.line >= 1) {
			/* we have only one line in our ID */
			str_printfa(str, " (parse error on offset %u)",
				    perr.offset);
		}
		*error_r = str_c(str);
		return -1;
	}
	return 0;
}

static int
fts_filter_normalizer_icu_filter(struct fts_filter *filter, const char **token,
				 const char **error_r)
{
	struct fts_filter_normalizer_icu *np =
		(struct fts_filter_normalizer_icu *)filter;
	UErrorCode err = U_ZERO_ERROR;
	UChar *utext = NULL;
	int32_t utext_cap = 0;
	int32_t utext_len = -1;
	int32_t utext_limit;

	if (np->transliterator == NULL) {
		if (fts_filter_normalizer_icu_create_trans(np, error_r) < 0)
			return -1;
	}

	make_uchar(*token, &utext, &utext_cap);
	utext_limit = u_strlen(utext);
	utrans_transUChars(np->transliterator, utext, &utext_len,
	                   utext_cap, 0, &utext_limit, &err);

	/* Data did not fit into utext. */
	if (utext_len > utext_cap || err == U_BUFFER_OVERFLOW_ERROR) {
		/* This is a crude retry fix... Make a new utext of the
		   size utrans_transUChars indicated */
		utext_len++; /* room for '\0' bytes(2) */
		utext_cap = utext_len;
		make_uchar(*token, &utext, &utext_cap);
		i_assert(utext_cap ==  utext_len);
		utext_limit = u_strlen(utext);
		utext_len = -1;
		err = U_ZERO_ERROR;
		utrans_transUChars(np->transliterator, utext,
		                   &utext_len, utext_cap, 0,
		                   &utext_limit, &err);
	}

	if (U_FAILURE(err)) {
		*error_r = t_strdup_printf("utrans_transUChars() failed: %s\n",
		                            u_errorName(err));
		return -1;
	}

	if (utext_len == 0)
		return 0;

	make_utf8(utext, token);
	return 1;
}

#else

static int
fts_filter_normalizer_icu_create(const struct fts_language *lang ATTR_UNUSED,
				 const char *const *settings ATTR_UNUSED,
				 struct fts_filter **filter_r ATTR_UNUSED,
				 const char **error_r)
{
	*error_r = "libicu support not built in";
	return -1;
}

static int
fts_filter_normalizer_icu_filter(struct fts_filter *filter ATTR_UNUSED,
				 const char **token ATTR_UNUSED,
				 const char **error_r ATTR_UNUSED)
{
	return -1;
}

static void
fts_filter_normalizer_icu_destroy(struct fts_filter *normalizer ATTR_UNUSED)
{
}

#endif

static const struct fts_filter_vfuncs normalizer_filter_vfuncs = {
	fts_filter_normalizer_icu_create,
	fts_filter_normalizer_icu_filter,
	fts_filter_normalizer_icu_destroy
};

static const struct fts_filter fts_filter_normalizer_icu_real = {
	.class_name = "normalizer-icu",
	.v = &normalizer_filter_vfuncs
};

const struct fts_filter *fts_filter_normalizer_icu =
	&fts_filter_normalizer_icu_real;
