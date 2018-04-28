/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "unichar.h"
#include "bsearch-insert-pos.h"
#include "fts-common.h"
#include "fts-tokenizer-private.h"
#include "fts-tokenizer-generic-private.h"
#include "fts-tokenizer-common.h"
#include "word-boundary-data.c"
#include "word-break-data.c"

#define FTS_DEFAULT_TOKEN_MAX_LENGTH 30
#define FTS_WB5A_PREFIX_MAX_LENGTH 3 /* Including apostrophe */

static unsigned char fts_ascii_word_breaks[128] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-15 */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 16-31 */

	1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, /* 32-47:  !"#$%&()*+,-./ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, /* 48-63: :;<=>? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 64-79: @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, /* 80-95: [\]^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 96-111: ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0  /* 112-127: {|}~ */
};

static int
fts_tokenizer_generic_create(const char *const *settings,
			     struct fts_tokenizer **tokenizer_r,
			     const char **error_r)
{
	struct generic_fts_tokenizer *tok;
	unsigned int max_length = FTS_DEFAULT_TOKEN_MAX_LENGTH;
	enum boundary_algorithm algo = BOUNDARY_ALGORITHM_SIMPLE;
	bool wb5a = FALSE;
	unsigned int i;

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i], *value = settings[i+1];

		if (strcmp(key, "maxlen") == 0) {
			if (str_to_uint(value, &max_length) < 0 ||
			    max_length == 0) {
				*error_r = t_strdup_printf(
					"Invalid maxlen setting: %s", value);
				return -1;
			}
		} else if (strcmp(key, "algorithm") == 0) {
			if (strcmp(value, ALGORITHM_TR29_NAME) == 0)
				algo = BOUNDARY_ALGORITHM_TR29;
			else if (strcmp(value, ALGORITHM_SIMPLE_NAME) == 0)
				;
			else {
				*error_r = t_strdup_printf(
				        "Invalid algorithm: %s", value);
				return -1;
			}
		} else if (strcmp(key, "search") == 0) {
			/* tokenizing a search string -
			   makes no difference to us */
		} else if (strcasecmp(key, "wb5a") == 0) {
			if (strcasecmp(value, "no") == 0)
				wb5a = FALSE;
			else
				wb5a = TRUE;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}

	if (wb5a && algo != BOUNDARY_ALGORITHM_TR29) {
		*error_r = "Can not use WB5a for algorithms other than TR29.";
		return -1;
	}

	tok = i_new(struct generic_fts_tokenizer, 1);
	if (algo == BOUNDARY_ALGORITHM_TR29)
		tok->tokenizer.v = &generic_tokenizer_vfuncs_tr29;
	else
		tok->tokenizer.v = &generic_tokenizer_vfuncs_simple;
	tok->max_length = max_length;
	tok->algorithm = algo;
	tok->wb5a = wb5a;
	tok->token = buffer_create_dynamic(default_pool, 64);

	*tokenizer_r = &tok->tokenizer;
	return 0;
}

static void
fts_tokenizer_generic_destroy(struct fts_tokenizer *_tok)
{
	struct generic_fts_tokenizer *tok =
		container_of(_tok, struct generic_fts_tokenizer, tokenizer);

	buffer_free(&tok->token);
	i_free(tok);
}

static bool
fts_tokenizer_generic_simple_current_token(struct generic_fts_tokenizer *tok,
                                           const char **token_r)
{
	const unsigned char *data = tok->token->data;
	size_t len = tok->token->used;

	if (tok->untruncated_length <= tok->max_length) {
		/* Remove the trailing apostrophe - it was made
		   into U+0027 earlier. There can be only a single such
		   apostrophe, because otherwise the token would have already
		   been split. We also want to remove the trailing apostrophe
		   only if it's the the last character in the nontruncated
		   token - a truncated token may end with apostrophe. */
		if (len > 0 && data[len-1] == '\'') {
			len--;
			i_assert(len > 0 && data[len-1] != '\'');
		}
	} else {
		fts_tokenizer_delete_trailing_partial_char(data, &len);
	}
	i_assert(len <= tok->max_length);

	*token_r = len == 0 ? "" :
		t_strndup(tok->token->data, len);
	buffer_set_used_size(tok->token, 0);
	tok->untruncated_length = 0;
	tok->prev_type = LETTER_TYPE_NONE;
	return len > 0;
}

static bool uint32_find(const uint32_t *data, unsigned int count,
			uint32_t value, unsigned int *idx_r)
{
	BINARY_NUMBER_SEARCH(data, count, value, idx_r);
}

static bool fts_uni_word_break(unichar_t c)
{
	unsigned int idx;

	/* Unicode General Punctuation, including deprecated characters. */
	if (c >= 0x2000 && c <= 0x206f)
		return TRUE;
	/* From word-break-data.c, which is generated from PropList.txt. */
	if (uint32_find(White_Space, N_ELEMENTS(White_Space), c, &idx))
		return TRUE;
	if (uint32_find(Dash, N_ELEMENTS(Dash), c, &idx))
		return TRUE;
	if (uint32_find(Quotation_Mark, N_ELEMENTS(Quotation_Mark), c, &idx))
		return TRUE;
	if (uint32_find(Terminal_Punctuation, N_ELEMENTS(Terminal_Punctuation), c, &idx))
		return TRUE;
	if (uint32_find(STerm, N_ELEMENTS(STerm), c, &idx))
		return TRUE;
	if (uint32_find(Pattern_White_Space, N_ELEMENTS(Pattern_White_Space), c, &idx))
		return TRUE;
	return FALSE;
}

static inline bool
fts_simple_is_word_break(struct generic_fts_tokenizer *tok,
			 unichar_t c, bool apostrophe)
{
	if (apostrophe)
		return tok->prev_type == LETTER_TYPE_SINGLE_QUOTE;
	else if (c < 0x80)
		return fts_ascii_word_breaks[c] != 0;
	else
		return fts_uni_word_break(c);
}

static void fts_tokenizer_generic_reset(struct fts_tokenizer *_tok)
{
	struct generic_fts_tokenizer *tok =
		container_of(_tok, struct generic_fts_tokenizer, tokenizer);

	tok->prev_type = LETTER_TYPE_NONE;
	tok->prev_prev_type = LETTER_TYPE_NONE;
	tok->untruncated_length = 0;
	buffer_set_used_size(tok->token, 0);
}

static void tok_append_truncated(struct generic_fts_tokenizer *tok,
				 const unsigned char *data, size_t size)
{
	buffer_append(tok->token, data,
		      I_MIN(size, tok->max_length - tok->token->used));
	tok->untruncated_length += size;
}

static int
fts_tokenizer_generic_simple_next(struct fts_tokenizer *_tok,
                                  const unsigned char *data, size_t size,
				  size_t *skip_r, const char **token_r,
				  const char **error_r ATTR_UNUSED)
{
	struct generic_fts_tokenizer *tok =
		container_of(_tok, struct generic_fts_tokenizer, tokenizer);
	size_t i, start = 0;
	int char_size;
	unichar_t c;
	bool apostrophe;

	for (i = 0; i < size; i += char_size) {
		char_size = uni_utf8_get_char_n(data + i, size - i, &c);
		i_assert(char_size > 0);

		apostrophe = IS_APOSTROPHE(c);
		if (fts_simple_is_word_break(tok, c, apostrophe)) {
			tok_append_truncated(tok, data + start, i - start);
			if (fts_tokenizer_generic_simple_current_token(tok, token_r)) {
				*skip_r = i + char_size;
				return 1;
			}
			start = i + char_size;
			/* it doesn't actually matter at this point how whether
			   subsequent apostrophes are handled by prefix
			   skipping or by ignoring empty tokens - they will be
			   dropped in any case. */
			tok->prev_type = LETTER_TYPE_NONE;
		} else if (apostrophe) {
			/* all apostrophes require special handling */
			const unsigned char apostrophe_char = '\'';

			tok_append_truncated(tok, data + start, i - start);
			if (tok->token->used > 0)
				tok_append_truncated(tok, &apostrophe_char, 1);
			start = i + char_size;
			tok->prev_type = LETTER_TYPE_SINGLE_QUOTE;
		} else {
			tok->prev_type = LETTER_TYPE_NONE;
		}
	}
	/* word boundary not found yet */
	tok_append_truncated(tok, data + start, i - start);
	*skip_r = i;

	/* return the last token */
	if (size == 0) {
		if (fts_tokenizer_generic_simple_current_token(tok, token_r))
			return 1;
	}

	return 0;
}

/* TODO: Arrange array searches roughly in order of likelihood of a match.
   TODO: Make some array of the arrays, so this can be a foreach loop.
   TODO: Check for Hangul.
   TODO: Add Hyphens U+002D HYPHEN-MINUS, U+2010 HYPHEN, possibly also
   U+058A ( ֊ ) ARMENIAN HYPHEN, and U+30A0 KATAKANA-HIRAGANA DOUBLE
   HYPHEN.
   TODO
*/
static enum letter_type letter_type(unichar_t c)
{
	unsigned int idx;

	if (IS_APOSTROPHE(c))
		return LETTER_TYPE_APOSTROPHE;
	if (uint32_find(CR, N_ELEMENTS(CR), c, &idx))
		return LETTER_TYPE_CR;
	if (uint32_find(LF, N_ELEMENTS(LF), c, &idx))
		return LETTER_TYPE_LF;
	if (uint32_find(Newline, N_ELEMENTS(Newline), c, &idx))
		return LETTER_TYPE_NEWLINE;
	if (uint32_find(Extend, N_ELEMENTS(Extend), c, &idx))
		return LETTER_TYPE_EXTEND;
	if (uint32_find(Regional_Indicator, N_ELEMENTS(Regional_Indicator), c, &idx))
		return LETTER_TYPE_REGIONAL_INDICATOR;
	if (uint32_find(Format, N_ELEMENTS(Format), c, &idx))
		return LETTER_TYPE_FORMAT;
	if (uint32_find(Katakana, N_ELEMENTS(Katakana), c, &idx))
		return LETTER_TYPE_KATAKANA;
	if (uint32_find(Hebrew_Letter, N_ELEMENTS(Hebrew_Letter), c, &idx))
		return LETTER_TYPE_HEBREW_LETTER;
	if (uint32_find(ALetter, N_ELEMENTS(ALetter), c, &idx))
		return LETTER_TYPE_ALETTER;
	if (uint32_find(Single_Quote, N_ELEMENTS(Single_Quote), c, &idx))
		return LETTER_TYPE_SINGLE_QUOTE;
	if (uint32_find(Double_Quote, N_ELEMENTS(Double_Quote), c, &idx))
		return LETTER_TYPE_DOUBLE_QUOTE;
	if (uint32_find(MidNumLet, N_ELEMENTS(MidNumLet), c, &idx))
		return LETTER_TYPE_MIDNUMLET;
	if (uint32_find(MidLetter, N_ELEMENTS(MidLetter), c, &idx))
		return LETTER_TYPE_MIDLETTER;
	if (uint32_find(MidNum, N_ELEMENTS(MidNum), c, &idx))
		return LETTER_TYPE_MIDNUM;
	if (uint32_find(Numeric, N_ELEMENTS(Numeric), c, &idx))
		return LETTER_TYPE_NUMERIC;
	if (uint32_find(ExtendNumLet, N_ELEMENTS(ExtendNumLet), c, &idx))
		return LETTER_TYPE_EXTENDNUMLET;
	return LETTER_TYPE_OTHER;
}

static bool letter_panic(struct generic_fts_tokenizer *tok ATTR_UNUSED)
{
	i_panic("Letter type should not be used.");
}

/* WB3, WB3a and WB3b, but really different since we try to eat
   whitespace between words. */
static bool letter_cr_lf_newline(struct generic_fts_tokenizer *tok ATTR_UNUSED)
{
	return TRUE;
}

static bool letter_extend_format(struct generic_fts_tokenizer *tok ATTR_UNUSED)
{
	/* WB4 */
	return FALSE;
}

static bool letter_regional_indicator(struct generic_fts_tokenizer *tok)
{
	/* WB13c */
	if (tok->prev_type == LETTER_TYPE_REGIONAL_INDICATOR)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_katakana(struct generic_fts_tokenizer *tok)
{
	/* WB13 */
	if (tok->prev_type == LETTER_TYPE_KATAKANA)
		return FALSE;

	/* WB13b */
	if (tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_hebrew(struct generic_fts_tokenizer *tok)
{
	/* WB5 */
	if (tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
		return FALSE;

	/* WB7 WB7c, except MidNumLet */
	if (tok->prev_prev_type == LETTER_TYPE_HEBREW_LETTER &&
	    (tok->prev_type == LETTER_TYPE_SINGLE_QUOTE ||
	     tok->prev_type == LETTER_TYPE_APOSTROPHE ||
	     tok->prev_type == LETTER_TYPE_MIDLETTER ||
	     tok->prev_type == LETTER_TYPE_DOUBLE_QUOTE))
		return FALSE;

	/* WB10 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	/* WB13b */
	if (tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_aletter(struct generic_fts_tokenizer *tok)
{

	/* WB5a */
	if (tok->wb5a && tok->token->used <= FTS_WB5A_PREFIX_MAX_LENGTH)
		if (IS_WB5A_APOSTROPHE(tok->prev_letter) && IS_VOWEL(tok->letter)) {
			tok->seen_wb5a = TRUE;
			return TRUE;
		}

	/* WB5 */
	if (tok->prev_type == LETTER_TYPE_ALETTER)
		return FALSE;

	/* WB7, except MidNumLet */
	if (tok->prev_prev_type == LETTER_TYPE_ALETTER &&
	    (tok->prev_type == LETTER_TYPE_SINGLE_QUOTE ||
	     tok->prev_type == LETTER_TYPE_APOSTROPHE ||
	     tok->prev_type == LETTER_TYPE_MIDLETTER))
		return FALSE;

	/* WB10 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	/* WB13b */
	if (tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;


	return TRUE; /* Any / Any */
}

static bool letter_single_quote(struct generic_fts_tokenizer *tok)
{
	/* WB6 */
	if (tok->prev_type == LETTER_TYPE_ALETTER ||
	    tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
		return FALSE;

	/* WB12 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_double_quote(struct generic_fts_tokenizer *tok)
{

	if (tok->prev_type == LETTER_TYPE_DOUBLE_QUOTE)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_midnumlet(struct generic_fts_tokenizer *tok ATTR_UNUSED)
{

	/* Break at MidNumLet, non-conformant with WB6/WB7 */
	return TRUE;
}

static bool letter_midletter(struct generic_fts_tokenizer *tok)
{
	/* WB6 */
	if (tok->prev_type == LETTER_TYPE_ALETTER ||
	    tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_midnum(struct generic_fts_tokenizer *tok)
{
	/* WB12 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_numeric(struct generic_fts_tokenizer *tok)
{
	/* WB8 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	/* WB9 */
	if (tok->prev_type == LETTER_TYPE_ALETTER ||
	    tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
		return FALSE;

	/* WB11 */
	if(tok->prev_prev_type == LETTER_TYPE_NUMERIC &&
	   (tok->prev_type == LETTER_TYPE_MIDNUM ||
	    tok->prev_type == LETTER_TYPE_MIDNUMLET ||
	    tok->prev_type == LETTER_TYPE_SINGLE_QUOTE))
		return FALSE;

	/* WB13b */
	if (tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_extendnumlet(struct generic_fts_tokenizer *tok)
{

	/* WB13a */
	if (tok->prev_type == LETTER_TYPE_ALETTER ||
	    tok->prev_type == LETTER_TYPE_HEBREW_LETTER ||
	    tok->prev_type == LETTER_TYPE_NUMERIC ||
	    tok->prev_type == LETTER_TYPE_KATAKANA ||
	    tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_apostrophe(struct generic_fts_tokenizer *tok)
{

       if (tok->prev_type == LETTER_TYPE_ALETTER ||
           tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
               return FALSE;

       return TRUE; /* Any / Any */
}

static bool letter_other(struct generic_fts_tokenizer *tok ATTR_UNUSED)
{
	return TRUE; /* Any / Any */
}

static inline void
add_prev_type(struct generic_fts_tokenizer *tok, enum letter_type lt)
{
	if(tok->prev_type != LETTER_TYPE_NONE)
		tok->prev_prev_type = tok->prev_type;
	tok->prev_type = lt;
}

static inline void
add_letter(struct generic_fts_tokenizer *tok, unichar_t c)
{
	if(tok->letter != 0)
		tok->prev_letter = tok->letter;
	tok->letter = c;
}

/*
   TODO: Define what to skip between words.
   TODO: Include double quotation marks? Messes up parsing?
   TODO: Does this "reverse approach" include too much in "whitespace"?
   TODO: Possibly use is_word_break()?
 */
static bool is_nontoken(enum letter_type lt)
{
	if (lt == LETTER_TYPE_REGIONAL_INDICATOR || lt == LETTER_TYPE_KATAKANA ||
	    lt == LETTER_TYPE_HEBREW_LETTER || lt == LETTER_TYPE_ALETTER ||
	    lt == LETTER_TYPE_NUMERIC)
		return FALSE;

	return TRUE;
}

/* The way things are done WB6/7 and WB11/12 "false positives" can
   leave trailing unwanted chars. They are searched for here. This is
   very kludgy and should be coded into the rules themselves
   somehow.
*/
static bool is_one_past_end(struct generic_fts_tokenizer *tok)
{
	/* WB6/7 false positive detected at one past end. */
	if (tok->prev_type == LETTER_TYPE_MIDLETTER ||
	    tok->prev_type == LETTER_TYPE_MIDNUMLET ||
	    tok->prev_type == LETTER_TYPE_APOSTROPHE ||
	    tok->prev_type == LETTER_TYPE_SINGLE_QUOTE )
		return TRUE;

	/* WB11/12 false positive detected at one past end. */
	if (tok->prev_type == LETTER_TYPE_MIDNUM ||
	    tok->prev_type == LETTER_TYPE_MIDNUMLET ||
	    tok->prev_type == LETTER_TYPE_APOSTROPHE ||
	    tok->prev_type == LETTER_TYPE_SINGLE_QUOTE)
		return TRUE;

	return FALSE;
}

static void
fts_tokenizer_generic_tr29_current_token(struct generic_fts_tokenizer *tok,
                                         const char **token_r)
{
	const unsigned char *data = tok->token->data;
	size_t len = tok->token->used;

	if (is_one_past_end(tok) &&
	    tok->untruncated_length <= tok->max_length) {
		/* delete the last character */
		while (!UTF8_IS_START_SEQ(data[len-1]))
			len--;
		i_assert(len > 0);
		len--;
	} else if (tok->untruncated_length > tok->max_length) {
		fts_tokenizer_delete_trailing_partial_char(data, &len);
	}
	/* we're skipping all non-token chars at the beginning of the word,
	   so by this point we must have something here - even if we just
	   deleted the last character */
	i_assert(len > 0);
	i_assert(len <= tok->max_length);

	tok->prev_prev_type = LETTER_TYPE_NONE;
	tok->prev_type = LETTER_TYPE_NONE;
	*token_r = t_strndup(data, len);
	buffer_set_used_size(tok->token, 0);
	tok->untruncated_length = 0;
}

static void wb5a_reinsert(struct generic_fts_tokenizer *tok)
{
	string_t *utf8_str = t_str_new(6);

	uni_ucs4_to_utf8_c(tok->letter, utf8_str);
	buffer_insert(tok->token, 0, str_data(utf8_str), str_len(utf8_str));
	tok->prev_type = letter_type(tok->letter);
	tok->letter = 0;
	tok->prev_letter = 0;
	tok->seen_wb5a = FALSE;
}

struct letter_fn {
	bool (*fn)(struct generic_fts_tokenizer *tok);
};
static struct letter_fn letter_fns[] = {
	{letter_panic}, {letter_cr_lf_newline}, {letter_cr_lf_newline},
	{letter_cr_lf_newline}, {letter_extend_format},
	{letter_regional_indicator}, {letter_extend_format},
	{letter_katakana}, {letter_hebrew}, {letter_aletter},
	{letter_single_quote}, {letter_double_quote},
	{letter_midnumlet}, {letter_midletter}, {letter_midnum},
	{letter_numeric}, {letter_extendnumlet}, {letter_panic},
	{letter_panic}, {letter_apostrophe}, {letter_other}
};

/*
  Find word boundaries in input text. Based on Unicode standard annex
  #29, but tailored for FTS purposes.
  http://www.unicode.org/reports/tr29/

  Note: The text of tr29 is a living standard, so it keeps
  changing. In newer specs some characters are combined, like AHLetter
  (ALetter | Hebrew_Letter) and MidNumLetQ (MidNumLet | Single_Quote).

  Adaptions:
  * Added optional WB5a as a configurable option. The cut of prefix is
   max FTS_WB5A_PREFIX chars.
  * No word boundary at Start-Of-Text or End-of-Text (Wb1 and WB2).
  * Break just once, not before and after.
  * Break at MidNumLet, except apostrophes (diverging from WB6/WB7).
  * Other things also (e.g. is_nontoken(), not really pure tr29. Meant
  to assist in finding individual words.
*/
static bool
uni_found_word_boundary(struct generic_fts_tokenizer *tok, enum letter_type lt)
{
	/* No rule knows what to do with just one char, except the linebreaks
	   we eat away (above) anyway. */
	if (tok->prev_type != LETTER_TYPE_NONE) {
		if (letter_fns[lt].fn(tok))
			return TRUE;
	}

	if (lt == LETTER_TYPE_EXTEND || lt == LETTER_TYPE_FORMAT) {
		/* These types are completely ignored. */
	} else {
		add_prev_type(tok,lt);
	}
	return FALSE;
}

static int
fts_tokenizer_generic_tr29_next(struct fts_tokenizer *_tok,
				const unsigned char *data, size_t size,
				size_t *skip_r, const char **token_r,
				const char **error_r ATTR_UNUSED)
{
	struct generic_fts_tokenizer *tok =
		container_of(_tok, struct generic_fts_tokenizer, tokenizer);
	unichar_t c;
	size_t i, char_start_i, start_pos = 0;
	enum letter_type lt;
	int char_size;

	for (i = 0; i < size; ) {
		char_start_i = i;
		char_size = uni_utf8_get_char_n(data + i, size - i, &c);
		i_assert(char_size > 0);
		i += char_size;
		lt = letter_type(c);

		/* The WB5a break is detected only when the "after
		   break" char is inspected. That char needs to be
		   reinserted as the "previous char". */
		if (tok->seen_wb5a)
			wb5a_reinsert(tok);

		if (tok->prev_type == LETTER_TYPE_NONE && is_nontoken(lt)) {
			/* Skip non-token chars at the beginning of token */
			i_assert(tok->token->used == 0);
			start_pos = i;
			continue;
		}

		if (tok->wb5a &&  tok->token->used <= FTS_WB5A_PREFIX_MAX_LENGTH)
			add_letter(tok, c);

		if (uni_found_word_boundary(tok, lt)) {
			i_assert(char_start_i >= start_pos && size >= start_pos);
			tok_append_truncated(tok, data + start_pos,
					     char_start_i - start_pos);
			*skip_r = i;
			fts_tokenizer_generic_tr29_current_token(tok, token_r);
			return 1;
		} else if (lt == LETTER_TYPE_APOSTROPHE ||
			   lt == LETTER_TYPE_SINGLE_QUOTE) {
			/* all apostrophes require special handling */
			const unsigned char apostrophe_char = '\'';
			tok_append_truncated(tok, data + start_pos,
					     char_start_i - start_pos);
			tok_append_truncated(tok, &apostrophe_char, 1);
			start_pos = i;
		}
	}
	i_assert(i >= start_pos && size >= start_pos);
	tok_append_truncated(tok, data + start_pos, i - start_pos);
	*skip_r = i;

	if (size == 0 && tok->token->used > 0) {
		/* return the last token */
		*skip_r = 0;
		fts_tokenizer_generic_tr29_current_token(tok, token_r);
		return 1;
	}
	return 0;
}

static int
fts_tokenizer_generic_next(struct fts_tokenizer *_tok ATTR_UNUSED,
			   const unsigned char *data ATTR_UNUSED,
                           size_t size ATTR_UNUSED,
                           size_t *skip_r ATTR_UNUSED,
			   const char **token_r ATTR_UNUSED,
			   const char **error_r ATTR_UNUSED)
{
	i_unreached();
}

static const struct fts_tokenizer_vfuncs generic_tokenizer_vfuncs = {
	fts_tokenizer_generic_create,
	fts_tokenizer_generic_destroy,
	fts_tokenizer_generic_reset,
	fts_tokenizer_generic_next
};

static const struct fts_tokenizer fts_tokenizer_generic_real = {
	.name = "generic",
	.v = &generic_tokenizer_vfuncs
};
const struct fts_tokenizer *fts_tokenizer_generic = &fts_tokenizer_generic_real;

const struct fts_tokenizer_vfuncs generic_tokenizer_vfuncs_simple = {
	fts_tokenizer_generic_create,
	fts_tokenizer_generic_destroy,
	fts_tokenizer_generic_reset,
	fts_tokenizer_generic_simple_next
};
const struct fts_tokenizer_vfuncs generic_tokenizer_vfuncs_tr29 = {
	fts_tokenizer_generic_create,
	fts_tokenizer_generic_destroy,
	fts_tokenizer_generic_reset,
	fts_tokenizer_generic_tr29_next
};
