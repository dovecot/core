/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "test-common.h"
#include "fts-icu.h"

#include <unicode/uclean.h>

static void test_fts_icu_utf8_to_utf16_ascii_resize(void)
{
	ARRAY_TYPE(icu_utf16) dest;

	test_begin("fts_icu_utf8_to_utf16 ascii resize");
	t_array_init(&dest, 2);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 4);
	fts_icu_utf8_to_utf16(&dest, "12");
	test_assert(array_count(&dest) == 2);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 4);

	fts_icu_utf8_to_utf16(&dest, "123");
	test_assert(array_count(&dest) == 3);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 7);

	fts_icu_utf8_to_utf16(&dest, "12345");
	test_assert(array_count(&dest) == 5);

	test_end();
}

static void test_fts_icu_utf8_to_utf16_32bit_resize(void)
{
	ARRAY_TYPE(icu_utf16) dest;
	unsigned int i;

	test_begin("fts_icu_utf8_to_utf16 32bit resize");
	for (i = 1; i <= 2; i++) {
		t_array_init(&dest, i);
		test_assert(buffer_get_writable_size(dest.arr.buffer) == i*2);
		fts_icu_utf8_to_utf16(&dest, "\xF0\x90\x90\x80"); /* 0x10400 */
		test_assert(array_count(&dest) == 2);
	}

	test_end();
}

static void test_fts_icu_utf16_to_utf8(void)
{
	string_t *dest = t_str_new(64);
	const UChar src[] = { 0xbd, 'b', 'c' };
	unsigned int i;

	test_begin("fts_icu_utf16_to_utf8");
	for (i = N_ELEMENTS(src); i > 0; i--) {
		fts_icu_utf16_to_utf8(dest, src, i);
		test_assert(dest->used == i+1);
	}
	test_end();
}

static void test_fts_icu_utf16_to_utf8_resize(void)
{
	string_t *dest;
	const UChar src = UNICODE_REPLACEMENT_CHAR;
	unsigned int i;

	test_begin("fts_icu_utf16_to_utf8 resize");
	for (i = 2; i <= 6; i++) {
		dest = t_str_new(i);
		test_assert(buffer_get_writable_size(dest) == i);
		fts_icu_utf16_to_utf8(dest, &src, 1);
		test_assert(dest->used == 3);
		test_assert(strcmp(str_c(dest), UNICODE_REPLACEMENT_CHAR_UTF8) == 0);
	}

	test_end();
}

static UTransliterator *get_translit(const char *id)
{
	UTransliterator *translit;
	ARRAY_TYPE(icu_utf16) id_utf16;
	UErrorCode err = U_ZERO_ERROR;
	UParseError perr;

	t_array_init(&id_utf16, 8);
	fts_icu_utf8_to_utf16(&id_utf16, id);
	translit = utrans_openU(array_first(&id_utf16),
				array_count(&id_utf16),
				UTRANS_FORWARD, NULL, 0, &perr, &err);
	test_assert(!U_FAILURE(err));
	return translit;
}

static void test_fts_icu_translate(void)
{
	const char *translit_id = "Any-Lower";
	UTransliterator *translit;
	ARRAY_TYPE(icu_utf16) dest;
	const UChar src[] = { 0xbd, 'B', 'C' };
	const char *error;
	unsigned int i;

	test_begin("fts_icu_translate");
	t_array_init(&dest, 32);
	translit = get_translit(translit_id);
	for (i = N_ELEMENTS(src); i > 0; i--) {
		array_clear(&dest);
		test_assert(fts_icu_translate(&dest, src, i,
					      translit, &error) == 0);
		test_assert(array_count(&dest) == i);
	}
	utrans_close(translit);
	test_end();
}

static void test_fts_icu_translate_resize(void)
{
	const char *translit_id = "Any-Hex";
	const char *src_utf8 = "FOO";
	ARRAY_TYPE(icu_utf16) src_utf16, dest;
	UTransliterator *translit;
	const char *error;
	unsigned int i;

	test_begin("fts_icu_translate_resize resize");

	t_array_init(&src_utf16, 8);
	translit = get_translit(translit_id);
	for (i = 1; i <= 10; i++) {
		array_clear(&src_utf16);
		fts_icu_utf8_to_utf16(&src_utf16, src_utf8);
		t_array_init(&dest, i);
		test_assert(buffer_get_writable_size(dest.arr.buffer) == i*2);
		test_assert(fts_icu_translate(&dest, array_first(&src_utf16),
					      array_count(&src_utf16),
					      translit, &error) == 0);
	}

	utrans_close(translit);
	test_end();
}

static void test_fts_icu_lcase(void)
{
	const char *src = "aBcD\xC3\x84\xC3\xA4";
	string_t *dest = t_str_new(64);

	test_begin("fts_icu_lcase");
	fts_icu_lcase(dest, src);
	test_assert(strcmp(str_c(dest), "abcd\xC3\xA4\xC3\xA4") == 0);
	test_end();
}

static void test_fts_icu_lcase_resize(void)
{
	const char *src = "a\xC3\x84";
	string_t *dest;
	unsigned int i;

	test_begin("fts_icu_lcase resize");
	for (i = 1; i <= 3; i++) {
		dest = t_str_new(i);
		test_assert(buffer_get_writable_size(dest) == i);
		fts_icu_lcase(dest, src);
		test_assert(strcmp(str_c(dest), "a\xC3\xA4") == 0);
		test_assert(buffer_get_writable_size(dest) == 3);
	}

	test_end();
}

static void test_fts_icu_lcase_resize_invalid_utf8(void)
{
	string_t *dest;

	test_begin("fts_icu_lcase resize invalid utf8");
	dest = t_str_new(1);
	fts_icu_lcase(dest, ".\x80.");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_fts_icu_utf8_to_utf16_ascii_resize,
		test_fts_icu_utf8_to_utf16_32bit_resize,
		test_fts_icu_utf16_to_utf8,
		test_fts_icu_utf16_to_utf8_resize,
		test_fts_icu_translate,
		test_fts_icu_translate_resize,
		test_fts_icu_lcase,
		test_fts_icu_lcase_resize,
		test_fts_icu_lcase_resize_invalid_utf8,
		NULL
	};
	int ret = test_run(test_functions);
	fts_icu_deinit();
	return ret;
}
