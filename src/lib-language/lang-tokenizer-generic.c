/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "str.h"
#include "unichar.h"
#include "bsearch-insert-pos.h"
#include "lang-common.h"
#include "lang-tokenizer-private.h"
#include "lang-tokenizer-generic-private.h"
#include "lang-tokenizer-common.h"
#include "lang-settings.h"
#include "word-boundary-data.c"
#include "word-break-data.c"

/* see comments below between is_base64() and skip_base64() */
#define LANG_SKIP_BASE64_MIN_SEQUENCES 1
#define LANG_SKIP_BASE64_MIN_CHARS 50
#define LANG_WB5A_PREFIX_MAX_LENGTH 3 /* Including apostrophe */

static unsigned char lang_ascii_word_breaks[128] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0-15 */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 16-31 */

	1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, /* 32-47:  !"#$%&()*+,-./ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, /* 48-63: :;<=>? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 64-79: @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, /* 80-95: [\]^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 96-111: ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0  /* 112-127: {|}~ */
};

struct algorithm {
	const char *name;
	enum boundary_algorithm id;
	const struct lang_tokenizer_vfuncs *v;
};

static const struct algorithm algorithms[] = {
	{ ALGORITHM_SIMPLE_NAME, BOUNDARY_ALGORITHM_SIMPLE, &generic_tokenizer_vfuncs_simple },
	{ ALGORITHM_TR29_NAME,   BOUNDARY_ALGORITHM_TR29,   &generic_tokenizer_vfuncs_tr29 },
	{ NULL, 0, NULL }
};

static const struct algorithm *parse_algorithm(const char *name)
{
	for (const struct algorithm *entry = algorithms; entry->name != NULL; entry++)
		if (strcmp(name, entry->name) == 0)
			return entry;
	return NULL;
}

static int
lang_tokenizer_generic_create(const struct lang_settings *set,
			      struct event *event ATTR_UNUSED,
			      enum lang_tokenizer_flags flags,
			      struct lang_tokenizer **tokenizer_r,
			      const char **error_r)
{
	const struct algorithm *algo = parse_algorithm(set->tokenizer_generic_algorithm);
	if (algo == NULL) {
		*error_r = t_strdup_printf(
			"Unknown language_tokenizer_generic_algorithm: %s",
			set->tokenizer_generic_algorithm);
		return -1;
	}

	bool wb5a = set->tokenizer_generic_wb5a;
	if (wb5a && algo->id != BOUNDARY_ALGORITHM_TR29) {
		*error_r = "Cannot use language_tokenizer_generic_wb5a for "
			   "algorithms other than language_tokenizer_generic_algorithm = tr29";
		return -1;
	}

	bool search = HAS_ALL_BITS(flags, LANG_TOKENIZER_FLAG_SEARCH);

	struct generic_lang_tokenizer *tok;
	tok = i_new(struct generic_lang_tokenizer, 1);
	tok->tokenizer.v = algo->v;
	tok->max_length = set->tokenizer_generic_token_maxlen;
	tok->algorithm = algo->id;
	tok->wb5a = wb5a;
	tok->prefixsplat = search && set->tokenizer_generic_explicit_prefix;
	tok->token = buffer_create_dynamic(default_pool, 64);

	*tokenizer_r = &tok->tokenizer;
	return 0;
}

static void
lang_tokenizer_generic_destroy(struct lang_tokenizer *_tok)
{
	struct generic_lang_tokenizer *tok =
		container_of(_tok, struct generic_lang_tokenizer, tokenizer);

	buffer_free(&tok->token);
	i_free(tok);
}

static inline void
shift_prev_type(struct generic_lang_tokenizer *tok, enum letter_type lt)
{
	tok->prev_prev_type = tok->prev_type;
	tok->prev_type = lt;
}

static inline void
add_prev_type(struct generic_lang_tokenizer *tok, enum letter_type lt)
{
	if(tok->prev_type != LETTER_TYPE_NONE)
		tok->prev_prev_type = tok->prev_type;
	tok->prev_type = lt;
}

static inline void
add_letter(struct generic_lang_tokenizer *tok, unichar_t c)
{
	if(tok->letter != 0)
		tok->prev_letter = tok->letter;
	tok->letter = c;
}

static bool
lang_tokenizer_generic_simple_current_token(struct generic_lang_tokenizer *tok,
                                            const char **token_r)
{
	const unsigned char *data = tok->token->data;
	size_t len = tok->token->used;

	if (tok->untruncated_length <= tok->max_length) {
		/* Remove the trailing apostrophe - it was made
		   into U+0027 earlier. There can be only a single such
		   apostrophe, because otherwise the token would have already
		   been split. We also want to remove the trailing apostrophe
		   only if it's the last character in the nontruncated
		   token - a truncated token may end with apostrophe. */
		if (len > 0 && data[len-1] == '\'') {
			len--;
			i_assert(len > 0 && data[len-1] != '\'');
		}
		if (len > 0 && data[len-1] == '*' && !tok->prefixsplat) {
			len--;
			i_assert(len > 0 && data[len-1] != '*');
		}
	} else {
		lang_tokenizer_delete_trailing_partial_char(data, &len);
	}
	i_assert(len <= tok->max_length);

	*token_r = len == 0 ? "" :
		t_strndup(tok->token->data, len);
	buffer_set_used_size(tok->token, 0);
	tok->untruncated_length = 0;
	return len > 0;
}

static bool uint32_find(const uint32_t *data, unsigned int count,
			uint32_t value, unsigned int *idx_r)
{
	BINARY_NUMBER_SEARCH(data, count, value, idx_r);
}

static bool lang_uni_word_break(unichar_t c)
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

enum lang_break_type {
	LANG_FROM_STOP = 0,
	LANG_FROM_WORD = 2,
	LANG_TO_STOP= 0,
	LANG_TO_WORD = 1,
#define FROM_TO(f,t) LANG_##f##_TO_##t = LANG_FROM_##f | LANG_TO_##t
	FROM_TO(STOP,STOP),
	FROM_TO(STOP,WORD),
	FROM_TO(WORD,STOP),
	FROM_TO(WORD,WORD),
};
static inline enum lang_break_type
lang_simple_is_word_break(const struct generic_lang_tokenizer *tok,
			 unichar_t c, bool apostrophe)
{
	/* Until we know better, a letter followed by an apostrophe is continuation of the word.
	   However, if we see non-word letters afterwards, we'll reverse that decision. */
	if (apostrophe)
		return tok->prev_type == LETTER_TYPE_ALETTER ? LANG_WORD_TO_WORD : LANG_STOP_TO_STOP;

	bool new_breakiness = (c < 0x80) ? (lang_ascii_word_breaks[c] != 0) : lang_uni_word_break(c);

	return (new_breakiness ? LANG_TO_STOP : LANG_TO_WORD)
		+ (tok->prev_type == LETTER_TYPE_ALETTER ||
		   tok->prev_type == LETTER_TYPE_SINGLE_QUOTE
		   ? LANG_FROM_WORD : LANG_FROM_STOP);
}

static void lang_tokenizer_generic_reset(struct lang_tokenizer *_tok)
{
	struct generic_lang_tokenizer *tok =
		container_of(_tok, struct generic_lang_tokenizer, tokenizer);

	tok->prev_type = LETTER_TYPE_NONE;
	tok->prev_prev_type = LETTER_TYPE_NONE;
	tok->untruncated_length = 0;
	buffer_set_used_size(tok->token, 0);
}

static void tok_append_truncated(struct generic_lang_tokenizer *tok,
				 const unsigned char *data, size_t size)
{
	buffer_append(tok->token, data,
		      I_MIN(size, tok->max_length - tok->token->used));
	tok->untruncated_length += size;
}

inline static bool
is_base64(const unsigned char ch)
{
	return base64_scheme.decmap[ch] != 0xff;
}

/* So far the following rule seems give good results in avoid indexing base64
   as keywords. It also seems to run well against base64 embedded
   headers, like ARC-Seal, DKIM-Signature, X-SG-EID, X-SG-ID, including
   encoded parts (e.g. =?us-ascii?Q?...?= sequences).

   leader characters   : [ \t\r\n=:;?]*
   matching characters : base64_scheme.decmap[ch] != 0xff
   trailing characters : none or [ \t\r\n=:;?] (other characters cause
                                                the run to be ignored)
   minimum run length  : 50
   minimum runs count  : 1

   i.e. (single or multiple) 50-chars runs of characters in the base64 set
        - excluded the trailing '=' - are recognized as base64 and ignored
	in indexing. */

#define allowed_base64_trailers allowed_base64_leaders
static unsigned char allowed_base64_leaders[] = {
	' ', '\t', '\r', '\n', '=', ';', ':', '?'
};

/* skip_base64() works doing lookahead on the data available in the tokenizer
   buffer, i.e. it is not able to see "what will come next" to perform more
   extensive matches. This implies that a very long base64 sequence, which is
   split halfway into two different chunks while feeding tokenizer, will be
   matched separately as the trailing part of first buffer and as the leading
   part of the second. Each of these two segments must fulfill the match
   criteria on its own to be discarded. What we pay is we will fail to reject
   small base64 chunks segments instead of rejecting the whole sequence.

   When skip_base64() is invoked in lang_tokenizer_generic_XX_next(), we know
   that we are not halfway the collection of a token.

   As (after the previous token) the buffer will contain non-token characters
   (i.e. token separators of some kind), we try to move forward among those
   until we find a base64 character. If we don't find one, there's nothing we
   can skip in the buffer and the skip phase terminates.

   If we found a base64 character, we check that the previous one is in
   allowed_base64_leaders[]; otherwise, the skip phase terminates.

   Now we try to determine how long the base64 sequence is. If it is too short,
   the skip phase terminates. It also terminates if there's a character
   in the buffer after the sequence and this is not in
   allowed_base64_trailers[].

   At this point we know that we have:
   - possibly a skipped sequence of non base64 characters ending with an
     allowed leader character, followed by:
   - a skipped sequence of base64 characters, possibly followed by an allowed
     trailed character
   we advance the start pointer to after the last skipped base64 character,
   and scan again to see if we can skip further chunks in the same way. */

static size_t
skip_base64(const unsigned char *data, size_t size)
{
	if (data == NULL) {
		i_assert(size == 0);
		return 0;
	}

	const unsigned char *start, *end = data + size;
	unsigned int matches = 0;
	for (start = data; start < end; ) {
		const unsigned char *first;
		for (first = start; first < end && !is_base64(*first); first++);
		if (first > start && memchr(allowed_base64_leaders, *(first - 1),
					    N_ELEMENTS(allowed_base64_leaders)) == NULL)
			break;

		const unsigned char *past;
		for (past = first; past < end && is_base64(*past); past++);
		if (past - first < LANG_SKIP_BASE64_MIN_CHARS)
			break;
		if (past < end && memchr(allowed_base64_trailers, *past,
					 N_ELEMENTS(allowed_base64_trailers)) == NULL)
			break;
		start = past;
		matches++;
	}
	return matches < LANG_SKIP_BASE64_MIN_SEQUENCES ? 0 : start - data;
}

static int
lang_tokenizer_generic_simple_next(struct lang_tokenizer *_tok,
                                   const unsigned char *data, size_t size,
				   size_t *skip_r, const char **token_r,
				   const char **error_r ATTR_UNUSED)
{
	struct generic_lang_tokenizer *tok =
		container_of(_tok, struct generic_lang_tokenizer, tokenizer);
	size_t i, start;
	int char_size;
	unichar_t c;
	bool apostrophe;
	enum lang_break_type break_type;

	start = tok->token->used > 0 ? 0 : skip_base64(data, size);
	for (i = start; i < size; i += char_size) {
		char_size = uni_utf8_get_char_n(data + i, size - i, &c);
		i_assert(char_size > 0);

		apostrophe = IS_APOSTROPHE(c);
		if ((tok->prefixsplat && IS_PREFIX_SPLAT(c)) &&
		    (tok->prev_type == LETTER_TYPE_ALETTER)) {
			/* this might be a prefix-matching query */
			shift_prev_type(tok, LETTER_TYPE_PREFIXSPLAT);
		} else if ((break_type = lang_simple_is_word_break(tok, c, apostrophe))
			   != LANG_WORD_TO_WORD) {
			tok_append_truncated(tok, data + start, i - start);
			shift_prev_type(tok, (break_type & LANG_TO_WORD) != 0
					? LETTER_TYPE_ALETTER : LETTER_TYPE_NONE);
			if (lang_tokenizer_generic_simple_current_token(tok, token_r)) {
				*skip_r = i;
				if (break_type != LANG_STOP_TO_WORD) /* therefore *_TO_STOP */
					*skip_r += char_size;
				return 1;
			}
			if ((break_type & LANG_TO_WORD) == 0)
				start = i + char_size;
		} else if (apostrophe) {
			/* all apostrophes require special handling */
			const unsigned char apostrophe_char = '\'';

			tok_append_truncated(tok, data + start, i - start);
			if (tok->token->used > 0)
				tok_append_truncated(tok, &apostrophe_char, 1);
			start = i + char_size;
			shift_prev_type(tok, LETTER_TYPE_SINGLE_QUOTE);
		} else {
			/* Lie slightly about the type. This is anything that
			   we're not skipping or cutting on and are prepared to
			   search for - it's "as good as" a letter. */
			shift_prev_type(tok, LETTER_TYPE_ALETTER);
		}
	}
	/* word boundary not found yet */
	if (i > start)
		tok_append_truncated(tok, data + start, i - start);
	*skip_r = i;

	/* return the last token */
	if (size == 0) {
		shift_prev_type(tok, LETTER_TYPE_NONE);
		if (lang_tokenizer_generic_simple_current_token(tok, token_r))
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
	if (IS_PREFIX_SPLAT(c)) /* prioritise appropriately */
		return LETTER_TYPE_PREFIXSPLAT;
	return LETTER_TYPE_OTHER;
}

static bool letter_panic(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{
	i_panic("Letter type should not be used.");
}

/* WB3, WB3a and WB3b, but really different since we try to eat
   whitespace between words. */
static bool letter_cr_lf_newline(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{
	return TRUE;
}

static bool letter_extend_format(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{
	/* WB4 */
	return FALSE;
}

static bool letter_regional_indicator(struct generic_lang_tokenizer *tok)
{
	/* WB13c */
	if (tok->prev_type == LETTER_TYPE_REGIONAL_INDICATOR)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_katakana(struct generic_lang_tokenizer *tok)
{
	/* WB13 */
	if (tok->prev_type == LETTER_TYPE_KATAKANA)
		return FALSE;

	/* WB13b */
	if (tok->prev_type == LETTER_TYPE_EXTENDNUMLET)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_hebrew(struct generic_lang_tokenizer *tok)
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

static bool letter_aletter(struct generic_lang_tokenizer *tok)
{

	/* WB5a */
	if (tok->wb5a && tok->token->used <= LANG_WB5A_PREFIX_MAX_LENGTH)
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

static bool letter_single_quote(struct generic_lang_tokenizer *tok)
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

static bool letter_double_quote(struct generic_lang_tokenizer *tok)
{

	if (tok->prev_type == LETTER_TYPE_DOUBLE_QUOTE)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_midnumlet(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{

	/* Break at MidNumLet, non-conformant with WB6/WB7 */
	return TRUE;
}

static bool letter_midletter(struct generic_lang_tokenizer *tok)
{
	/* WB6 */
	if (tok->prev_type == LETTER_TYPE_ALETTER ||
	    tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_midnum(struct generic_lang_tokenizer *tok)
{
	/* WB12 */
	if (tok->prev_type == LETTER_TYPE_NUMERIC)
		return FALSE;

	return TRUE; /* Any / Any */
}

static bool letter_numeric(struct generic_lang_tokenizer *tok)
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

static bool letter_extendnumlet(struct generic_lang_tokenizer *tok)
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

static bool letter_apostrophe(struct generic_lang_tokenizer *tok)
{

       if (tok->prev_type == LETTER_TYPE_ALETTER ||
           tok->prev_type == LETTER_TYPE_HEBREW_LETTER)
               return FALSE;

       return TRUE; /* Any / Any */
}
static bool letter_prefixsplat(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{
	/* Dovecot explicit-prefix specific */
	return TRUE; /* Always induces a word break - but with special handling */
}
static bool letter_other(struct generic_lang_tokenizer *tok ATTR_UNUSED)
{
	return TRUE; /* Any / Any */
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
static bool is_one_past_end(struct generic_lang_tokenizer *tok)
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
lang_tokenizer_generic_tr29_current_token(struct generic_lang_tokenizer *tok,
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
		lang_tokenizer_delete_trailing_partial_char(data, &len);
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

static void wb5a_reinsert(struct generic_lang_tokenizer *tok)
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
	bool (*fn)(struct generic_lang_tokenizer *tok);
};
static struct letter_fn letter_fns[] = {
	{letter_panic}, {letter_cr_lf_newline}, {letter_cr_lf_newline},
	{letter_cr_lf_newline}, {letter_extend_format},
	{letter_regional_indicator}, {letter_extend_format},
	{letter_katakana}, {letter_hebrew}, {letter_aletter},
	{letter_single_quote}, {letter_double_quote},
	{letter_midnumlet}, {letter_midletter}, {letter_midnum},
	{letter_numeric}, {letter_extendnumlet}, {letter_panic},
	{letter_panic}, {letter_apostrophe}, {letter_prefixsplat},
	{letter_other}
};

/*
  Find word boundaries in input text. Based on Unicode standard annex
  #29, but tailored for language purposes.
  http://www.unicode.org/reports/tr29/

  Note: The text of tr29 is a living standard, so it keeps
  changing. In newer specs some characters are combined, like AHLetter
  (ALetter | Hebrew_Letter) and MidNumLetQ (MidNumLet | Single_Quote).

  Adaptions:
  * Added optional WB5a as a configurable option. The cut of prefix is
   max LANG_WB5A_PREFIX chars.
  * No word boundary at Start-Of-Text or End-of-Text (Wb1 and WB2).
  * Break just once, not before and after.
  * Break at MidNumLet, except apostrophes (diverging from WB6/WB7).
  * Other things also (e.g. is_nontoken(), not really pure tr29. Meant
  to assist in finding individual words.
*/
static bool
uni_found_word_boundary(struct generic_lang_tokenizer *tok, enum letter_type lt)
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
lang_tokenizer_generic_tr29_next(struct lang_tokenizer *_tok,
				 const unsigned char *data, size_t size,
				 size_t *skip_r, const char **token_r,
				 const char **error_r ATTR_UNUSED)
{
	struct generic_lang_tokenizer *tok =
		container_of(_tok, struct generic_lang_tokenizer, tokenizer);
	unichar_t c;
	size_t i, char_start_i, start_pos;
	enum letter_type lt;
	int char_size;

	start_pos = tok->token->used > 0 ? 0 : skip_base64(data, size);
	for (i = start_pos; i < size; ) {
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

		if (tok->wb5a &&  tok->token->used <= LANG_WB5A_PREFIX_MAX_LENGTH)
			add_letter(tok, c);

		if (uni_found_word_boundary(tok, lt)) {
			i_assert(char_start_i >= start_pos && size >= start_pos);
			tok_append_truncated(tok, data + start_pos,
					     char_start_i - start_pos);
			if (lt == LETTER_TYPE_PREFIXSPLAT && tok->prefixsplat) {
				const unsigned char prefix_char = LANG_PREFIX_SPLAT_CHAR;
				tok_append_truncated(tok, &prefix_char, 1);
			}
			*skip_r = i;
			lang_tokenizer_generic_tr29_current_token(tok, token_r);
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
	if (i > start_pos)
		tok_append_truncated(tok, data + start_pos, i - start_pos);
	*skip_r = i;

	if (size == 0 && tok->token->used > 0) {
		/* return the last token */
		*skip_r = 0;
		lang_tokenizer_generic_tr29_current_token(tok, token_r);
		return 1;
	}
	return 0;
}

static int
lang_tokenizer_generic_next(struct lang_tokenizer *_tok ATTR_UNUSED,
			    const unsigned char *data ATTR_UNUSED,
                            size_t size ATTR_UNUSED,
                            size_t *skip_r ATTR_UNUSED,
			    const char **token_r ATTR_UNUSED,
			    const char **error_r ATTR_UNUSED)
{
	i_unreached();
}

static const struct lang_tokenizer_vfuncs generic_tokenizer_vfuncs = {
	lang_tokenizer_generic_create,
	lang_tokenizer_generic_destroy,
	lang_tokenizer_generic_reset,
	lang_tokenizer_generic_next
};

static const struct lang_tokenizer lang_tokenizer_generic_real = {
	.name = "generic",
	.v = &generic_tokenizer_vfuncs
};
const struct lang_tokenizer *lang_tokenizer_generic = &lang_tokenizer_generic_real;

const struct lang_tokenizer_vfuncs generic_tokenizer_vfuncs_simple = {
	lang_tokenizer_generic_create,
	lang_tokenizer_generic_destroy,
	lang_tokenizer_generic_reset,
	lang_tokenizer_generic_simple_next
};
const struct lang_tokenizer_vfuncs generic_tokenizer_vfuncs_tr29 = {
	lang_tokenizer_generic_create,
	lang_tokenizer_generic_destroy,
	lang_tokenizer_generic_reset,
	lang_tokenizer_generic_tr29_next
};
