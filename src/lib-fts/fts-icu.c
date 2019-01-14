/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mempool.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "fts-icu.h"

#include <unicode/uchar.h>
#include <unicode/ucasemap.h>
#include <unicode/uclean.h>

static struct UCaseMap *icu_csm = NULL;

static struct UCaseMap *fts_icu_csm(void)
{
	UErrorCode err = U_ZERO_ERROR;

	if (icu_csm != NULL)
		return icu_csm;
	icu_csm = ucasemap_open(NULL, U_FOLD_CASE_DEFAULT, &err);
	if (U_FAILURE(err)) {
		i_fatal("LibICU ucasemap_open() failed: %s",
			u_errorName(err));
	}
	return icu_csm;
}

void fts_icu_utf8_to_utf16(ARRAY_TYPE(icu_utf16) *dest_utf16,
			   const char *src_utf8)
{
	buffer_t *dest_buf = dest_utf16->arr.buffer;
	UErrorCode err = U_ZERO_ERROR;
	size_t src_bytes = strlen(src_utf8);
	int32_t utf16_len;
	UChar *dest_data, *retp = NULL;
	int32_t avail_uchars = 0;

	/* try to encode with the current buffer size */
	avail_uchars = buffer_get_writable_size(dest_buf) / sizeof(UChar);
	dest_data = buffer_get_space_unsafe(dest_buf, 0,
				buffer_get_writable_size(dest_buf));
	retp = u_strFromUTF8Lenient(dest_data, avail_uchars,
				    &utf16_len, src_utf8, src_bytes, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		/* try again with a larger buffer */
		dest_data = buffer_get_space_unsafe(dest_buf, 0,
						    utf16_len * sizeof(UChar));
		err = U_ZERO_ERROR;
		retp = u_strFromUTF8Lenient(dest_data, utf16_len,
					    &utf16_len, src_utf8,
					    src_bytes, &err);
	}
	if (U_FAILURE(err)) {
		i_panic("LibICU u_strFromUTF8Lenient() failed: %s",
			u_errorName(err));
	}
	buffer_set_used_size(dest_buf, utf16_len * sizeof(UChar));
	i_assert(retp == dest_data);
}

void fts_icu_utf16_to_utf8(string_t *dest_utf8, const UChar *src_utf16,
			   unsigned int src_len)
{
	int32_t dest_len = 0;
	int32_t sub_num = 0;
	char *dest_data, *retp = NULL;
	UErrorCode err = U_ZERO_ERROR;

	/* try to encode with the current buffer size */
	dest_data = buffer_get_space_unsafe(dest_utf8, 0,
					    buffer_get_writable_size(dest_utf8));
	retp = u_strToUTF8WithSub(dest_data, buffer_get_writable_size(dest_utf8),
				  &dest_len, src_utf16, src_len,
				  UNICODE_REPLACEMENT_CHAR, &sub_num, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		/* try again with a larger buffer */
		dest_data = buffer_get_space_unsafe(dest_utf8, 0, dest_len);
		err = U_ZERO_ERROR;
		retp = u_strToUTF8WithSub(dest_data, buffer_get_writable_size(dest_utf8), &dest_len,
					  src_utf16, src_len,
					  UNICODE_REPLACEMENT_CHAR,
					  &sub_num, &err);
	}
	if (U_FAILURE(err)) {
		i_panic("LibICU u_strToUTF8WithSub() failed: %s",
			u_errorName(err));
	}
	buffer_set_used_size(dest_utf8, dest_len);
	i_assert(retp == dest_data);
}

int fts_icu_translate(ARRAY_TYPE(icu_utf16) *dest_utf16, const UChar *src_utf16,
		      unsigned int src_len, UTransliterator *transliterator,
		      const char **error_r)
{
	buffer_t *dest_buf = dest_utf16->arr.buffer;
	UErrorCode err = U_ZERO_ERROR;
	int32_t utf16_len = src_len;
	UChar *dest_data;
	int32_t avail_uchars, limit = src_len;
	size_t dest_pos = dest_buf->used;

	/* translation is done in-place in the buffer. try first with the
	   current buffer size. */
	array_append(dest_utf16, src_utf16, src_len);

	avail_uchars = (buffer_get_writable_size(dest_buf)-dest_pos) / sizeof(UChar);
	dest_data = buffer_get_space_unsafe(dest_buf, dest_pos,
			buffer_get_writable_size(dest_buf) - dest_pos);
	utrans_transUChars(transliterator, dest_data, &utf16_len,
			   avail_uchars, 0, &limit, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
		/* try again with a larger buffer */
		err = U_ZERO_ERROR;
		avail_uchars = utf16_len;
		limit = utf16_len = src_len;
		buffer_write(dest_buf, dest_pos,
			     src_utf16, src_len*sizeof(UChar));
		dest_data = buffer_get_space_unsafe(dest_buf, dest_pos,
						    avail_uchars * sizeof(UChar));
		utrans_transUChars(transliterator, dest_data, &utf16_len,
				   avail_uchars, 0, &limit, &err);
		i_assert(err != U_BUFFER_OVERFLOW_ERROR);
	}
	if (U_FAILURE(err)) {
		*error_r = t_strdup_printf("LibICU utrans_transUChars() failed: %s",
					   u_errorName(err));
		buffer_set_used_size(dest_buf, dest_pos);
		return -1;
	}
	buffer_set_used_size(dest_buf, utf16_len * sizeof(UChar));
	return 0;
}

void fts_icu_lcase(string_t *dest_utf8, const char *src_utf8)
{
	struct UCaseMap *csm = fts_icu_csm();
	size_t avail_bytes, dest_pos = dest_utf8->used;
	char *dest_data;
	int dest_full_len;
	UErrorCode err = U_ZERO_ERROR;

	avail_bytes = buffer_get_writable_size(dest_utf8) - dest_pos;
	dest_data = buffer_get_space_unsafe(dest_utf8, dest_pos, avail_bytes);

	/* ucasemap_utf8ToLower() may need to be called multiple times, because
	   the first return value may not be large enough. */
	for (unsigned int i = 0;; i++) {
		dest_full_len = ucasemap_utf8ToLower(csm, dest_data, avail_bytes,
						     src_utf8, -1, &err);
		if (err != U_BUFFER_OVERFLOW_ERROR || i == 2)
			break;

		err = U_ZERO_ERROR;
		dest_data = buffer_get_space_unsafe(dest_utf8, dest_pos, dest_full_len);
		avail_bytes = dest_full_len;
	}
	if (U_FAILURE(err)) {
		i_fatal("LibICU ucasemap_utf8ToLower() failed: %s",
			u_errorName(err));
	}
	buffer_set_used_size(dest_utf8, dest_full_len);
}

void fts_icu_deinit(void)
{
	if (icu_csm != NULL) {
		ucasemap_close(icu_csm);
		icu_csm = NULL;
	}
	u_cleanup();
}

int fts_icu_transliterator_create(const char *id,
                                  UTransliterator **transliterator_r,
                                  const char **error_r)
{
	UErrorCode err = U_ZERO_ERROR;
	UParseError perr;
	ARRAY_TYPE(icu_utf16) id_utf16;
	i_zero(&perr);

	t_array_init(&id_utf16, strlen(id));
	fts_icu_utf8_to_utf16(&id_utf16, id);
	*transliterator_r = utrans_openU(array_front(&id_utf16),
					 array_count(&id_utf16),
					 UTRANS_FORWARD, NULL, 0, &perr, &err);
	if (U_FAILURE(err)) {
		string_t *str = t_str_new(128);

		str_printfa(str, "Failed to open transliterator for id '%s': %s",
			    id, u_errorName(err));
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
