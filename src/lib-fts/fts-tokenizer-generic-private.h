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
	LETTER_TYPE_APOSTROPHE, /* Own modification to TR29 */
	LETTER_TYPE_OTHER /* WB14 "any" */
};

enum boundary_algorithm {
	BOUNDARY_ALGORITHM_NONE = 0,
	BOUNDARY_ALGORITHM_SIMPLE,
#define ALGORITHM_SIMPLE_NAME "simple"
	BOUNDARY_ALGORITHM_TR29
#define ALGORITHM_TR29_NAME "tr29"
};

struct generic_fts_tokenizer {
	struct fts_tokenizer tokenizer;
	unsigned int max_length;
	bool wb5a; /* TR29 rule for prefix separation
	              in e.g. French or Italian. */
	bool seen_wb5a;
	unichar_t prev_letter;
	unichar_t letter;
	enum boundary_algorithm algorithm;
	enum letter_type prev_type;
	enum letter_type prev_prev_type;
	size_t untruncated_length;
	buffer_t *token;
};

#endif
