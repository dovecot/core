/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "unicode-data.h"
#include "unicode-transform.h"
#include "lang-filter-private.h"
#include "lang-settings.h"
#include "language.h"
#include "lang-filter-normalizer-icu.h"

#include <ctype.h>

/* The normalizer-icu filter is implemented internally for these libicu
   transliterator IDs. They all lowercase, NFKD-decompose and remove
   nonspacing marks. The output is the same as libicu's, except for runs of
   more than 30 non-starters: Dovecot's normalization inserts CGJs into them
   (Stream-Safe Text Format) and doesn't reorder across them. The CGJs added
   by NFKD are removed as nonspacing marks. Any other ID is handed over to
   the lang_filter_normalizer_icu module, which uses libicu. */
struct lang_filter_normalizer_rule {
	const char *id;
	/* NFC-compose after removing nonspacing marks */
	bool nfc;
	/* Remove U+0020 spaces at the end */
	bool remove_spaces;
};

static const struct lang_filter_normalizer_rule lang_filter_normalizer_rules[] = {
	{ .id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC; [\\x20] Remove",
	  .nfc = TRUE, .remove_spaces = TRUE },
	{ .id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; [\\x20] Remove",
	  .remove_spaces = TRUE },
	{ .id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC",
	  .nfc = TRUE },
	{ .id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove" },
};

struct lang_filter_normalizer {
	struct lang_filter filter;
	const struct lang_filter_normalizer_rule *rule;
	/* Decoded input token */
	ARRAY_TYPE(uint32_t) cps;

	/* Transform chain: Any-Lower -> NFKD -> [: Nonspacing Mark :] Remove
	   -> NFC (optional) -> [\x20] Remove and output as UTF-8 */
	struct unicode_casemap lowercase;
	struct unicode_nf_context nfkd, nfc;
	struct unicode_transform remove_mn;
	struct unicode_transform sink;
};

static ssize_t
lang_filter_normalizer_remove_mn_input(
	struct unicode_transform *trans,
	const struct unicode_transform_buffer *buf, const char **error_r);
static ssize_t
lang_filter_normalizer_sink_input(struct unicode_transform *trans,
				  const struct unicode_transform_buffer *buf,
				  const char **error_r);

static const struct unicode_transform_def
lang_filter_normalizer_remove_mn_def = {
	.input = lang_filter_normalizer_remove_mn_input,
};

static const struct unicode_transform_def lang_filter_normalizer_sink_def = {
	.input = lang_filter_normalizer_sink_input,
};

static const struct lang_filter_normalizer_rule *
lang_filter_normalizer_rule_find(const char *id)
{
	const struct lang_filter_normalizer_rule *rule;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(lang_filter_normalizer_rules); i++) {
		rule = &lang_filter_normalizer_rules[i];
		if (strcmp(rule->id, id) == 0)
			return rule;
	}
	return NULL;
}

static int
lang_filter_normalizer_icu_create_module(const struct lang_settings *set,
					 struct event *event,
					 struct lang_filter **filter_r,
					 const char **error_r)
{
	const struct lang_filter *icu_class;
	int ret;

	ret = lang_filter_module_load(LANG_FILTER_NORMALIZER_ICU_MODULE_NAME,
				      &icu_class, error_r);
	if (ret == 0) {
		*error_r = t_strdup_printf(
			"language_filter_normalizer_icu_id '%s' requires libicu, "
			"but the "LANG_FILTER_NORMALIZER_ICU_MODULE_NAME
			" module isn't installed in %s",
			set->filter_normalizer_icu_id, lang_filter_module_dir);
		return -1;
	}
	if (ret < 0)
		return -1;
	return icu_class->v.create(set, event, filter_r, error_r);
}

static int
lang_filter_normalizer_icu_create(const struct lang_settings *set,
				  struct event *event,
				  struct lang_filter **filter_r,
				  const char **error_r)
{
	const struct lang_filter_normalizer_rule *rule;
	struct lang_filter_normalizer *np;

	rule = lang_filter_normalizer_rule_find(set->filter_normalizer_icu_id);
	if (rule == NULL) {
		return lang_filter_normalizer_icu_create_module(
			set, event, filter_r, error_r);
	}

	np = i_new(struct lang_filter_normalizer, 1);
	np->filter = *lang_filter_normalizer_icu;
	np->filter.token = str_new(default_pool, 64);
	np->rule = rule;
	i_array_init(&np->cps, 64);

	unicode_casemap_init_lowercase_final_sigma(&np->lowercase);
	unicode_nf_init(&np->nfkd, UNICODE_NFKD);
	unicode_transform_init(&np->remove_mn,
			       &lang_filter_normalizer_remove_mn_def);
	unicode_transform_init(&np->sink, &lang_filter_normalizer_sink_def);

	unicode_transform_chain(&np->lowercase.transform, &np->nfkd.transform);
	unicode_transform_chain(&np->nfkd.transform, &np->remove_mn);
	if (rule->nfc) {
		unicode_nf_init(&np->nfc, UNICODE_NFC);
		unicode_transform_chain(&np->remove_mn, &np->nfc.transform);
		unicode_transform_chain(&np->nfc.transform, &np->sink);
	} else {
		unicode_transform_chain(&np->remove_mn, &np->sink);
	}
	*filter_r = &np->filter;
	return 0;
}

static void lang_filter_normalizer_icu_destroy(struct lang_filter *filter)
{
	struct lang_filter_normalizer *np =
		container_of(filter, struct lang_filter_normalizer, filter);

	array_free(&np->cps);
	str_free(&np->filter.token);
	i_free(np);
}

static bool
lang_filter_normalizer_ascii(struct lang_filter_normalizer *np,
			     const char *token)
{
	const char *p;

	for (p = token; *p != '\0'; p++) {
		if ((unsigned char)*p >= 0x80)
			return FALSE;
	}

	/* NFKD and NFC don't change ASCII and there are no nonspacing marks */
	for (p = token; *p != '\0'; p++) {
		if (*p != ' ' || !np->rule->remove_spaces)
			str_append_c(np->filter.token, i_tolower(*p));
	}
	return TRUE;
}

static void
lang_filter_normalizer_decode(struct lang_filter_normalizer *np,
			      const char *token)
{
	const unsigned char *input = (const unsigned char *)token;
	size_t size = strlen(token);
	uint32_t chr;
	bool bad_cp = FALSE;

	array_clear(&np->cps);
	while (size > 0) {
		int bytes = uni_utf8_get_char_n(input, size, &chr);
		if (bytes <= 0) {
			/* Invalid input. Replace each invalid sequence with a
			   single replacement character. */
			input++; size--;
			if (bad_cp)
				continue;
			chr = UNICODE_REPLACEMENT_CHAR;
			bad_cp = TRUE;
		} else {
			input += bytes;
			size -= bytes;
			bad_cp = FALSE;
		}
		array_push_back(&np->cps, &chr);
	}
}

static ssize_t
lang_filter_normalizer_remove_mn_forward(
	struct unicode_transform *trans,
	const struct unicode_transform_buffer *buf, size_t start, size_t end,
	const char **error_r)
{
	if (start == end)
		return 0;
	return uniform_transform_forward(trans, &buf->cp[start],
					 (buf->cp_data == NULL ? NULL :
					  &buf->cp_data[start]),
					 end - start, error_r);
}

static ssize_t
lang_filter_normalizer_remove_mn_input(
	struct unicode_transform *trans,
	const struct unicode_transform_buffer *buf, const char **error_r)
{
	const struct unicode_code_point_data *cp_data;
	size_t i, start = 0;
	ssize_t sret;

	/* [: Nonspacing Mark :] Remove: Forward the code points between the
	   nonspacing marks */
	for (i = 0; i < buf->cp_count; i++) {
		cp_data = (buf->cp_data == NULL ? NULL : buf->cp_data[i]);
		if (cp_data == NULL)
			cp_data = unicode_code_point_get_data(buf->cp[i]);
		if (cp_data->general_category != UNICODE_GENERAL_CATEGORY_MN)
			continue;

		sret = lang_filter_normalizer_remove_mn_forward(trans, buf,
								start, i,
								error_r);
		if (sret < 0)
			return -1;
		if ((size_t)sret < i - start)
			return start + sret;
		start = i + 1;
	}
	sret = lang_filter_normalizer_remove_mn_forward(trans, buf, start,
							buf->cp_count, error_r);
	if (sret < 0)
		return -1;
	return start + sret;
}

static ssize_t
lang_filter_normalizer_sink_input(struct unicode_transform *trans,
				  const struct unicode_transform_buffer *buf,
				  const char **error_r ATTR_UNUSED)
{
	struct lang_filter_normalizer *np =
		container_of(trans, struct lang_filter_normalizer, sink);
	size_t i;

	/* [\x20] Remove */
	for (i = 0; i < buf->cp_count; i++) {
		if (buf->cp[i] != ' ' || !np->rule->remove_spaces)
			uni_ucs4_to_utf8_c(buf->cp[i], np->filter.token);
	}
	return buf->cp_count;
}

static void lang_filter_normalizer_run(struct lang_filter_normalizer *np)
{
	const uint32_t *cps;
	unsigned int count;
	const char *error;
	ssize_t sret;
	int ret;

	unicode_nf_reset(&np->nfkd);
	if (np->rule->nfc)
		unicode_nf_reset(&np->nfc);

	/* The transforms in the chain never fail and the sink accepts
	   everything */
	cps = array_get(&np->cps, &count);
	sret = unicode_transform_input(&np->lowercase.transform, cps, count,
				       &error);
	i_assert(sret == (ssize_t)count);
	ret = unicode_transform_flush(&np->lowercase.transform, &error);
	i_assert(ret > 0);
}

static int
lang_filter_normalizer_icu_filter(struct lang_filter *filter,
				  const char **token,
				  const char **error_r ATTR_UNUSED)
{
	struct lang_filter_normalizer *np =
		container_of(filter, struct lang_filter_normalizer, filter);

	str_truncate(np->filter.token, 0);
	if (!lang_filter_normalizer_ascii(np, *token)) {
		lang_filter_normalizer_decode(np, *token);
		lang_filter_normalizer_run(np);
	}
	if (str_len(np->filter.token) == 0)
		return 0;
	*token = str_c(np->filter.token);
	return 1;
}

static const struct lang_filter lang_filter_normalizer_icu_real = {
	.class_name = "normalizer-icu",
	.v = {
		lang_filter_normalizer_icu_create,
		lang_filter_normalizer_icu_filter,
		lang_filter_normalizer_icu_destroy
	}
};

const struct lang_filter *lang_filter_normalizer_icu =
	&lang_filter_normalizer_icu_real;
