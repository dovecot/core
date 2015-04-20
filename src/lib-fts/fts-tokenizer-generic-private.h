#ifndef FTS_TOKENIZER_GENERIC_PRIVATE_H
#define FTS_TOKENIZER_GENERIC_PRIVATE_H

extern const struct fts_tokenizer_vfuncs generic_tokenizer_vfuncs_simple;
extern const struct fts_tokenizer_vfuncs generic_tokenizer_vfuncs_tr29;

/* Word boundary letter type */
enum letter_type {
	LETTER_TYPE_NONE = 0,
	LETTER_TYPE_CR,
	LETTER_TYPE_LF,
	LETTER_TYPE_NEWLINE,
	LETTER_TYPE_EXTEND,
	LETTER_TYPE_REGIONAL_INDICATOR,
	LETTER_TYPE_FORMAT,
	LETTER_TYPE_KATAKANA,
	LETTER_TYPE_HEBREW_LETTER,
	LETTER_TYPE_ALETTER,
	LETTER_TYPE_SINGLE_QUOTE,
	LETTER_TYPE_DOUBLE_QUOTE,
	LETTER_TYPE_MIDNUMLET,
	LETTER_TYPE_MIDLETTER,
	LETTER_TYPE_MIDNUM,
	LETTER_TYPE_NUMERIC,
	LETTER_TYPE_EXTENDNUMLET,
	LETTER_TYPE_SOT,
	LETTER_TYPE_EOT,
	LETTER_TYPE_OTHER /* WB14 "any" */
};

enum boundary_algorithm {
	BOUNDARY_ALGORITHM_NONE = 0,
	BOUNDARY_ALGORITHM_SIMPLE,
#define ALGORITHM_SIMPLE_NAME "simple" /* TODO: could be public in
                                          fts-tokenizer.h */
	BOUNDARY_ALGORITHM_TR29
#define ALGORITHM_TR29_NAME "tr29"
};

struct generic_fts_tokenizer {
	struct fts_tokenizer tokenizer;
	unsigned int max_length;
	enum boundary_algorithm algorithm;
	enum letter_type prev_letter; /* These two are basically the
	                                     state of the parsing. */
	enum letter_type prev_prev_letter;
	size_t last_size; /* Bytes in latest utf8 character. */
	buffer_t *token;
};

static bool letter_panic(struct generic_fts_tokenizer *tok);
static bool letter_cr_lf_newline(struct generic_fts_tokenizer *tok);
static bool letter_extend_format(struct generic_fts_tokenizer *tok);
static bool letter_regional_indicator(struct generic_fts_tokenizer *tok);
static bool letter_katakana(struct generic_fts_tokenizer *tok);
static bool letter_hebrew(struct generic_fts_tokenizer *tok);
static bool letter_aletter(struct generic_fts_tokenizer *tok);
static bool letter_single_quote(struct generic_fts_tokenizer *tok);
static bool letter_double_quote(struct generic_fts_tokenizer *tok);
static bool letter_midnumlet(struct generic_fts_tokenizer *tok);
static bool letter_midletter(struct generic_fts_tokenizer *tok);
static bool letter_midnum(struct generic_fts_tokenizer *tok);
static bool letter_numeric(struct generic_fts_tokenizer *tok);
static bool letter_extendnumlet(struct generic_fts_tokenizer *tok);
static bool letter_other(struct generic_fts_tokenizer *tok);

struct letter_fn {
	bool (*fn)(struct generic_fts_tokenizer *tok);
};
struct letter_fn letter_fns[] = {
	{letter_panic}, {letter_cr_lf_newline}, {letter_cr_lf_newline},
	{letter_cr_lf_newline}, {letter_extend_format},
	{letter_regional_indicator}, {letter_extend_format},
	{letter_katakana}, {letter_hebrew}, {letter_aletter},
	{letter_single_quote}, {letter_double_quote},
	{letter_midnumlet}, {letter_midletter}, {letter_midnum},
	{letter_numeric}, {letter_extendnumlet}, {letter_panic},
	{letter_panic}, {letter_other}
};
#endif
