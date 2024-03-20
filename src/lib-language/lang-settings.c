/* Copyright (c) 2023 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-parser.h"
#include "lang-settings.h"

/* <settings checks> */
static bool langs_settings_ext_check(struct event *event, void *_set,
				     pool_t pool, const char **error_r);
/* </settings checks> */

#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	"language_"#name, name, struct lang_settings)

static const struct setting_define lang_setting_defines[] = {
	DEF(STR, name),
	SETTING_DEFINE_STRUCT_BOOL("language_default", is_default, struct lang_settings),
	DEF(BOOLLIST, filters),
	DEF(STR,  filter_normalizer_icu_id),
	DEF(STR,  filter_stopwords_dir),
	DEF(BOOLLIST, tokenizers),
	DEF(UINT, tokenizer_address_token_maxlen),
	DEF(STR,  tokenizer_generic_algorithm),
	DEF(BOOL, tokenizer_generic_explicit_prefix),
	DEF(UINT, tokenizer_generic_token_maxlen),
	DEF(BOOL, tokenizer_generic_wb5a),
	SETTING_DEFINE_LIST_END
};

const struct lang_settings lang_default_settings = {
	.name = "",
	.is_default = FALSE,
	.filters = ARRAY_INIT,
	.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC; [\\x20] Remove",
	.filter_stopwords_dir = DATADIR"/stopwords",
	.tokenizers = ARRAY_INIT,
	.tokenizer_address_token_maxlen = 250,
	.tokenizer_generic_algorithm = "simple",
	.tokenizer_generic_explicit_prefix = FALSE,
	.tokenizer_generic_token_maxlen = 30,
	.tokenizer_generic_wb5a = FALSE,
};

const struct setting_parser_info lang_setting_parser_info = {
	.name = "language",

	.defines = lang_setting_defines,
	.defaults = &lang_default_settings,

	.struct_size = sizeof(struct lang_settings),
	.pool_offset1 = 1 + offsetof(struct lang_settings, pool),
};

#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	#name, name, struct langs_settings)

static const struct setting_define langs_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = "language",
	  .offset = offsetof(struct langs_settings, languages),
	  .filter_array_field_name = "language_name", },
	DEF(STR, textcat_config_path),
	SETTING_DEFINE_LIST_END
};

static const struct langs_settings langs_default_settings = {
	.textcat_config_path = "",
};

const struct setting_parser_info langs_setting_parser_info = {
	.name = "languages",

	.defines = langs_setting_defines,
	.defaults = &langs_default_settings,
	.ext_check_func = langs_settings_ext_check,

	.struct_size = sizeof(struct langs_settings),
	.pool_offset1 = 1 + offsetof(struct langs_settings, pool),
};

/* <settings checks> */

static bool langs_settings_ext_check(struct event *event, void *_set,
				     pool_t pool, const char **error_r)
{
	struct langs_settings *set = _set;
	if (array_is_empty(&set->languages)) {
#ifdef CONFIG_BINARY
		return TRUE;
#else
		*error_r = "No language { .. } defined";
		return FALSE;
#endif
	}

	const char *lang_default = NULL;
	const char *filter_name;
	unsigned int nondata_languages = 0;
	p_array_init(&set->parsed_languages, pool, array_count(&set->languages));
	array_foreach_elem(&set->languages, filter_name) {
		const struct lang_settings *lang_set;
		const char *error;

		if (settings_get_filter(event, "language", filter_name,
					&lang_setting_parser_info, 0,
					&lang_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get language %s: %s",
				filter_name, error);
			return FALSE;
		}

		bool is_data = strcmp(lang_set->name, LANGUAGE_DATA) == 0;

		if (lang_set->is_default) {
			if (is_data) {
				*error_r = "language "LANGUAGE_DATA" cannot have { default = yes }";
				settings_free(lang_set);
				return FALSE;
			}

			if (lang_default != NULL) {
				*error_r = t_strdup_printf(
					"Only one language with with { default = yes } is allowed"
					" (default is '%s', cannot set '%s' too)",
					lang_default, lang_set->name);
				settings_free(lang_set);
				return FALSE;
			}
			lang_default = t_strdup(lang_set->name);
		}

		if (!is_data)
			nondata_languages++;

		struct lang_settings *lang_set_dup =
			p_memdup(pool, lang_set, sizeof(*lang_set));
		pool_add_external_ref(pool, lang_set->pool);
		if (lang_set->is_default)
			array_push_front(&set->parsed_languages, &lang_set_dup);
		else
			array_push_back(&set->parsed_languages, &lang_set_dup);
		settings_free(lang_set);
	}

	if (nondata_languages == 0) {
		*error_r = "No valid languages";
		return FALSE;
	}

	if (lang_default == NULL) {
		*error_r = "No language with { default = yes } found";
		return FALSE;
	}

	return TRUE;
}

/* </settings checks> */
