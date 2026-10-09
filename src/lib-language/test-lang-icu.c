/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "unicode-data.h"
#include "test-common.h"
#include "lang-filter-private.h"
#include "lang-settings.h"
#include "lang-icu.h"
#include "lang-filter-normalizer-icu.h"

#include <stdio.h>
#include <unicode/uchar.h>
#include <unicode/uclean.h>

#define NORMALIZER_COMPARE_BATCH_SIZE 64
#define NORMALIZER_COMPARE_MAX_REPORTS 20

/* UDHRDIR comes from Automake AM_CPPFLAGS */
#define UDHR_FRA_NAME "/udhr_fra.txt"

static const char *const builtin_normalizer_ids[] = {
	"Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC; [\\x20] Remove",
	"Any-Lower; NFKD; [: Nonspacing Mark :] Remove; [\\x20] Remove",
	"Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC",
	"Any-Lower; NFKD; [: Nonspacing Mark :] Remove",
};

struct normalizer_compare {
	struct lang_filter *builtin, *icu;
	unsigned int reports;
};

static void test_lang_icu_utf8_to_utf16_ascii_resize(void)
{
	ARRAY_TYPE(icu_utf16) dest;

	test_begin("lang_icu_utf8_to_utf16 ascii resize");
	t_array_init(&dest, 2);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 4);
	lang_icu_utf8_to_utf16(&dest, "12");
	test_assert(array_count(&dest) == 2);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 4);

	lang_icu_utf8_to_utf16(&dest, "123");
	test_assert(array_count(&dest) == 3);
	test_assert(buffer_get_writable_size(dest.arr.buffer) == 7);

	lang_icu_utf8_to_utf16(&dest, "12345");
	test_assert(array_count(&dest) == 5);

	test_end();
}

static void test_lang_icu_utf8_to_utf16_32bit_resize(void)
{
	ARRAY_TYPE(icu_utf16) dest;
	unsigned int i;

	test_begin("lang_icu_utf8_to_utf16 32bit resize");
	for (i = 1; i <= 2; i++) {
		t_array_init(&dest, i);
		test_assert(buffer_get_writable_size(dest.arr.buffer) == i*2);
		lang_icu_utf8_to_utf16(&dest, "\xF0\x90\x90\x80"); /* 0x10400 */
		test_assert(array_count(&dest) == 2);
	}

	test_end();
}

static void test_lang_icu_utf16_to_utf8(void)
{
	string_t *dest = t_str_new(64);
	const UChar src[] = { 0xbd, 'b', 'c' };
	unsigned int i;

	test_begin("lang_icu_utf16_to_utf8");
	for (i = N_ELEMENTS(src); i > 0; i--) {
		lang_icu_utf16_to_utf8(dest, src, i);
		test_assert(dest->used == i+1);
	}
	test_end();
}

static void test_lang_icu_utf16_to_utf8_resize(void)
{
	string_t *dest;
	const UChar src = UNICODE_REPLACEMENT_CHAR;
	unsigned int i;

	test_begin("lang_icu_utf16_to_utf8 resize");
	for (i = 2; i <= 6; i++) {
		dest = t_str_new(i);
		test_assert(buffer_get_writable_size(dest) == i);
		lang_icu_utf16_to_utf8(dest, &src, 1);
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
	lang_icu_utf8_to_utf16(&id_utf16, id);
	translit = utrans_openU(array_front(&id_utf16),
				array_count(&id_utf16),
				UTRANS_FORWARD, NULL, 0, &perr, &err);
	test_assert(!U_FAILURE(err));
	return translit;
}

static void test_lang_icu_translate(void)
{
	const char *translit_id = "Any-Lower";
	UTransliterator *translit;
	ARRAY_TYPE(icu_utf16) dest;
	const UChar src[] = { 0xbd, 'B', 'C' };
	const char *error;
	unsigned int i;

	test_begin("lang_icu_translate");
	t_array_init(&dest, 32);
	translit = get_translit(translit_id);
	for (i = N_ELEMENTS(src); i > 0; i--) {
		array_clear(&dest);
		test_assert(lang_icu_translate(&dest, src, i,
					      translit, &error) == 0);
		test_assert(array_count(&dest) == i);
	}
	utrans_close(translit);
	test_end();
}

static void test_lang_icu_translate_resize(void)
{
	const char *translit_id = "Any-Hex";
	const char *src_utf8 = "FOO";
	ARRAY_TYPE(icu_utf16) src_utf16, dest;
	UTransliterator *translit;
	const char *error;
	unsigned int i;

	test_begin("lang_icu_translate_resize resize");

	t_array_init(&src_utf16, 8);
	translit = get_translit(translit_id);
	for (i = 1; i <= 10; i++) {
		array_clear(&src_utf16);
		lang_icu_utf8_to_utf16(&src_utf16, src_utf8);
		t_array_init(&dest, i);
		test_assert(buffer_get_writable_size(dest.arr.buffer) == i*2);
		test_assert(lang_icu_translate(&dest, array_front(&src_utf16),
					      array_count(&src_utf16),
					      translit, &error) == 0);
	}

	utrans_close(translit);
	test_end();
}

static void
normalizer_compare_init(struct normalizer_compare *ctx_r, const char *id)
{
	struct lang_settings set = lang_default_settings;
	const char *error;

	i_zero(ctx_r);
	set.filter_normalizer_icu_id = id;
	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, &set,
				       NULL, &ctx_r->builtin, &error) == 0);
	test_assert(lang_filter_create(&lang_filter_normalizer_icu_class,
				       NULL, &set, NULL, &ctx_r->icu,
				       &error) == 0);
	/* make sure the built-in implementation is really used */
	test_assert(ctx_r->builtin->v.filter !=
		    lang_filter_normalizer_icu_class.v.filter);
}

static void normalizer_compare_deinit(struct normalizer_compare *ctx)
{
	lang_filter_unref(&ctx->builtin);
	lang_filter_unref(&ctx->icu);
}

static bool
normalizer_compare_token(struct normalizer_compare *ctx, const char *input,
			 const char *descr)
{
	const char *builtin_token = input, *icu_token = input, *error;
	int builtin_ret, icu_ret;

	builtin_ret = lang_filter(ctx->builtin, &builtin_token, &error);
	if (builtin_ret < 0)
		i_fatal("built-in normalizer failed: %s", error);
	builtin_token = t_strdup(builtin_token);
	icu_ret = lang_filter(ctx->icu, &icu_token, &error);
	if (icu_ret < 0)
		i_fatal("libicu normalizer failed: %s", error);

	if (builtin_ret == icu_ret &&
	    null_strcmp(builtin_token, icu_token) == 0)
		return TRUE;
	if (descr != NULL && ctx->reports++ < NORMALIZER_COMPARE_MAX_REPORTS) {
		test_failed(t_strdup_printf(
			"%s: built-in '%s' != libicu '%s'", descr,
			builtin_token == NULL ? "" : builtin_token,
			icu_token == NULL ? "" : icu_token));
	}
	return FALSE;
}

static bool normalizer_compare_want_cp(uint32_t cp)
{
	const struct unicode_code_point_data *cp_data;

	if (cp == 0 || (cp >= UTF16_SURROGATE_HIGH_FIRST &&
			cp <= UTF16_SURROGATE_LOW_LAST))
		return FALSE;
	/* Code points not assigned in both Unicode versions can differ */
	if (u_isdefined((UChar32)cp) == 0 ||
	    !unicode_code_point_is_assigned(cp))
		return FALSE;
	cp_data = unicode_code_point_get_data(cp);
	if (cp_data->general_category == UNICODE_GENERAL_CATEGORY_CO)
		return FALSE;

	/* Skip code points whose properties changed between the Unicode
	   versions, e.g. U+0295 isn't cased anymore since Unicode 18. */
	if ((u_hasBinaryProperty((UChar32)cp, UCHAR_CASED) != 0) !=
	    cp_data->pb_c_cased)
		return FALSE;
	if ((u_hasBinaryProperty((UChar32)cp, UCHAR_CASE_IGNORABLE) != 0) !=
	    cp_data->pb_c_case_ignorable)
		return FALSE;
	if ((u_charType((UChar32)cp) == U_NON_SPACING_MARK) !=
	    (cp_data->general_category == UNICODE_GENERAL_CATEGORY_MN))
		return FALSE;
	if (u_getCombiningClass((UChar32)cp) !=
	    cp_data->canonical_combining_class)
		return FALSE;
	return TRUE;
}

static void
normalizer_compare_add_plain(string_t *str, uint32_t cp)
{
	uni_ucs4_to_utf8_c(cp, str);
}

#define GREEK_CAPITAL_SIGMA_UTF8 "\xCE\xA3"
static void
normalizer_compare_add_sigma(string_t *str, uint32_t cp)
{
	/* Test the code point as the Final_Sigma context. '1' is neither
	   cased nor case-ignorable, so it separates the contexts. */
	str_append(str, "A"GREEK_CAPITAL_SIGMA_UTF8);
	uni_ucs4_to_utf8_c(cp, str);
	str_append(str, "1");
	uni_ucs4_to_utf8_c(cp, str);
	str_append(str, GREEK_CAPITAL_SIGMA_UTF8"1A");
	uni_ucs4_to_utf8_c(cp, str);
	str_append(str, GREEK_CAPITAL_SIGMA_UTF8"1");
}

static void
normalizer_compare_batch(struct normalizer_compare *ctx, const uint32_t *cps,
			 unsigned int count,
			 void (*add)(string_t *str, uint32_t cp))
{
	string_t *str = t_str_new(256);
	unsigned int i;

	for (i = 0; i < count; i++)
		add(str, cps[i]);
	if (normalizer_compare_token(ctx, str_c(str), NULL))
		return;

	/* find out which code points differ */
	for (i = 0; i < count; i++) {
		str_truncate(str, 0);
		add(str, cps[i]);
		(void)normalizer_compare_token(ctx, str_c(str),
			t_strdup_printf("U+%04X", cps[i]));
	}
	if (ctx->reports == 0) {
		str_truncate(str, 0);
		for (i = 0; i < count; i++)
			add(str, cps[i]);
		(void)normalizer_compare_token(ctx, str_c(str),
			t_strdup_printf("U+%04X..U+%04X", cps[0],
					cps[count - 1]));
	}
}

static void
normalizer_compare_all_cps(struct normalizer_compare *ctx,
			   void (*add)(string_t *str, uint32_t cp))
{
	uint32_t cps[NORMALIZER_COMPARE_BATCH_SIZE];
	unsigned int count = 0;
	uint32_t cp;

	for (cp = 0; cp <= UNICHAR_T_MAX; cp++) {
		if (!normalizer_compare_want_cp(cp))
			continue;
		cps[count++] = cp;
		if (count == N_ELEMENTS(cps)) {
			T_BEGIN {
				normalizer_compare_batch(ctx, cps, count, add);
			} T_END;
			count = 0;
		}
	}
	if (count > 0) T_BEGIN {
		normalizer_compare_batch(ctx, cps, count, add);
	} T_END;
}

static void test_lang_icu_normalizer_compare_cps(void)
{
	struct normalizer_compare ctx;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(builtin_normalizer_ids); i++) {
		test_begin(t_strdup_printf(
			"normalizer built-in vs libicu: all code points (%s)",
			builtin_normalizer_ids[i]));
		normalizer_compare_init(&ctx, builtin_normalizer_ids[i]);
		normalizer_compare_all_cps(&ctx, normalizer_compare_add_plain);
		normalizer_compare_deinit(&ctx);
		test_end();
	}
}

static void test_lang_icu_normalizer_compare_final_sigma(void)
{
	struct normalizer_compare ctx;

	test_begin("normalizer built-in vs libicu: final sigma context");
	normalizer_compare_init(&ctx, builtin_normalizer_ids[0]);
	normalizer_compare_all_cps(&ctx, normalizer_compare_add_sigma);
	normalizer_compare_deinit(&ctx);
	test_end();
}

static void test_lang_icu_normalizer_compare_text(void)
{
	static const char *const tokens[] = {
		"Vem",
		"\xC3\x85\xC3\x84\xC3\x96",
		("Vem kan segla f\xC3\xB6rutan vind?\n"
		 "\xC3\x85\xC3\x84\xC3\x96\xC3\xB6\xC3\xA4\xC3\xA5"),
		"\xCE\x9F\xCE\x94\xCE\x9F\xCE\xA3 \xCE\xA3\xCE\x91",
		"A\xCE\xA3\xCD\x85 1\xCD\x85\xCE\xA3",
		"\xEF\xAC\x81 \xE2\x84\xAB \xC2\xA0 \xE2\x80\x83x",
		"\xC4\xB0stanbul \xE1\xBA\x9E \xC3\x9F",
		"\xED\x95\x9C\xEA\xB5\xAD\xEC\x96\xB4",
	};
	struct normalizer_compare ctx;
	char buf[1024];
	unsigned int i, j;
	FILE *input;

	test_begin("normalizer built-in vs libicu: text");
	for (i = 0; i < N_ELEMENTS(builtin_normalizer_ids); i++) {
		normalizer_compare_init(&ctx, builtin_normalizer_ids[i]);
		for (j = 0; j < N_ELEMENTS(tokens); j++) {
			(void)normalizer_compare_token(&ctx, tokens[j],
				t_strdup_printf("%s: %s", builtin_normalizer_ids[i],
						tokens[j]));
		}

		input = fopen(UDHRDIR UDHR_FRA_NAME, "r");
		test_assert(input != NULL);
		while (input != NULL && fgets(buf, sizeof(buf), input) != NULL) T_BEGIN {
			(void)normalizer_compare_token(&ctx, buf,
				t_strdup_printf("%s: %s", builtin_normalizer_ids[i],
						buf));
		} T_END;
		if (input != NULL)
			fclose(input);
		normalizer_compare_deinit(&ctx);
	}
	test_end();
}

static void test_lang_icu_normalizer_invalid_id(void)
{
	struct lang_filter *norm = NULL;
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-One-Out-There; DKFN; [: Nonspacing Mark :] Remove";
	const char *error = NULL, *token = "foo";

	test_begin("normalizer libicu invalid id");
	test_assert(lang_filter_create(&lang_filter_normalizer_icu_class, NULL,
				       &set, NULL, &norm, &error) == 0);
	test_assert(lang_filter(norm, &token, &error) < 0 && error != NULL);
	lang_filter_unref(&norm);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_lang_icu_utf8_to_utf16_ascii_resize,
		test_lang_icu_utf8_to_utf16_32bit_resize,
		test_lang_icu_utf16_to_utf8,
		test_lang_icu_utf16_to_utf8_resize,
		test_lang_icu_translate,
		test_lang_icu_translate_resize,
		test_lang_icu_normalizer_compare_text,
		test_lang_icu_normalizer_compare_cps,
		test_lang_icu_normalizer_compare_final_sigma,
		test_lang_icu_normalizer_invalid_id,
		NULL
	};
	int ret;

	lang_filter_normalizer_icu_init(NULL);
	ret = test_run(test_functions);
	lang_filter_normalizer_icu_deinit();
	return ret;
}
