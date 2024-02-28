#ifndef LANG_SETTINGS_H
#define LANG_SETTINGS_H

#include "array.h"

/* <settings checks> */
#define LANGUAGE_DATA "data"
/* </settings checks> */

ARRAY_DEFINE_TYPE(lang_settings, struct lang_settings *);
struct lang_settings {
	pool_t pool;
	const char *name;
	const char *filter_normalizer_icu_id;
	const char *filter_stopwords_dir;
	const char *tokenizer_generic_algorithm;
	ARRAY_TYPE(const_string) filters;
	ARRAY_TYPE(const_string) tokenizers;
	unsigned int tokenizer_address_token_maxlen;
	unsigned int tokenizer_generic_token_maxlen;
	bool tokenizer_generic_explicit_prefix;
	bool tokenizer_generic_wb5a;
	bool is_default;
};

struct langs_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) languages;
	const char *textcat_config_path;

	ARRAY_TYPE(lang_settings) parsed_languages;
};

extern const struct lang_settings lang_default_settings;
extern const struct setting_parser_info langs_setting_parser_info;

#endif
