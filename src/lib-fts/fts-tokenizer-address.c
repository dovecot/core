/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "buffer.h"
#include "fts-tokenizer-private.h"

#define FTS_DEFAULT_NO_PARENT FALSE
#define FTS_DEFAULT_SEARCH FALSE

enum email_address_parser_state {
	EMAIL_ADDRESS_PARSER_STATE_NONE = 0,
	EMAIL_ADDRESS_PARSER_STATE_LOCALPART,
	EMAIL_ADDRESS_PARSER_STATE_DOMAIN,
	EMAIL_ADDRESS_PARSER_STATE_COMPLETE
};

struct email_address_fts_tokenizer {
	struct fts_tokenizer tokenizer;
	enum email_address_parser_state state;
	string_t *last_word;
	string_t *parent_data; /* Copy of input data between tokens.
	                          TODO: could be buffer_t maybe */
	bool no_parent;
	bool search;
};

/*
   Extracted from core rfc822-parser.c

   atext        =       ALPHA / DIGIT / ; Any character except controls,
                        "!" / "#" /     ;  SP, and specials.
                        "$" / "%" /     ;  Used for atoms
                        "&" / "'" /
                        "*" / "+" /
                        "-" / "/" /
                        "=" / "?" /
                        "^" / "_" /
                        "`" / "{" /
                        "|" / "}" /
                        "~"

  MIME:

  token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
              or tspecials>
  tspecials :=  "(" / ")" / "<" / ">" / "@" /
                "," / ";" / ":" / "\" / <">
                "/" / "[" / "]" / "?" / "="

  So token is same as dot-atom, except stops also at '/', '?' and '='.
*/

/* atext chars are marked with 1, alpha and digits with 2,
   atext-but-mime-tspecials with 4 */
unsigned char rfc822_atext_chars[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0-15 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 16-31 */
	0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 4, /* 32-47 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 4, 0, 4, /* 48-63 */
	0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 64-79 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 1, 1, /* 80-95 */
	1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 96-111 */
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 0, /* 112-127 */

	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
};

#define IS_ATEXT(c) \
	(rfc822_atext_chars[(int)(unsigned char)(c)] != 0)
#define IS_DTEXT(c) \
	(rfc822_atext_chars[(int)(unsigned char)(c)] == 2)


static int
fts_tokenizer_email_address_create(const char *const *settings,
				   struct fts_tokenizer **tokenizer_r,
				   const char **error_r)
{
	struct email_address_fts_tokenizer *tok;
	bool no_parent = FTS_DEFAULT_NO_PARENT;
	bool search = FTS_DEFAULT_SEARCH;
	unsigned int i;

	for (i = 0; settings[i] != NULL; i += 2) {
		const char *key = settings[i];

		if (strcmp(key, "no_parent") == 0) {
			no_parent = TRUE;
		}else if (strcmp(key, "search") == 0) {
			search = TRUE;
		} else {
			*error_r = t_strdup_printf("Unknown setting: %s", key);
			return -1;
		}
	}

	tok = i_new(struct email_address_fts_tokenizer, 1);
	tok->tokenizer = *fts_tokenizer_email_address;
	tok->last_word = str_new(default_pool, 128);
	tok->parent_data = str_new(default_pool, 128);
	tok->no_parent = no_parent;
	tok->search = search;
	*tokenizer_r = &tok->tokenizer;
	return 0;
}

static void fts_tokenizer_email_address_destroy(struct fts_tokenizer *_tok)
{
	struct email_address_fts_tokenizer *tok =
		(struct email_address_fts_tokenizer *)_tok;

	str_free(&tok->last_word);
	str_free(&tok->parent_data);
	i_free(tok);
}

static int
fts_tokenizer_address_current_token(struct email_address_fts_tokenizer *tok,
                                    const char **token_r)
{
	tok->tokenizer.skip_parents = TRUE;
	tok->state = EMAIL_ADDRESS_PARSER_STATE_NONE;
	*token_r = t_strdup(str_c(tok->last_word));
	return 1;
}

static int
fts_tokenizer_address_parent_data(struct email_address_fts_tokenizer *tok,
                                  const char **token_r)
{
	/* TODO: search option removes address from data here. */
	if (tok->search && tok->state >= EMAIL_ADDRESS_PARSER_STATE_DOMAIN)
		i_debug("Would remove current token");

	*token_r = t_strdup(str_c(tok->parent_data));
	str_truncate(tok->parent_data, 0);
	return 1;
}

/* Used to rewind past characters that can not be the start of a new localpart.
 Returns size that can be skipped. */
static size_t skip_nonlocal_part(const unsigned char *data, size_t size)
{
	const unsigned char *p = data;
	size_t skip = 0;

	/* Yes, a dot can start an address. De facto before de jure. */
	while ( skip < size && (!IS_ATEXT(*p) && *p != '.')) {
		skip++;
		p++;
	}
	return skip;
}

/* TODO: 
   - DONT dereference *p past size!
*/
static enum email_address_parser_state
fts_tokenizer_email_address_parse_local(struct email_address_fts_tokenizer *tok,
                                        const unsigned char *data, size_t size,
                                        size_t *skip_r)
{
	size_t pos = 0;
	const unsigned char *p = data;
	bool at = FALSE;

	while (pos < size && (IS_ATEXT(*p) || (*p == '@' || *p == '.'))) {
		if (*p == '@')
			at = TRUE;
		pos++;
		p++;
		if (at)
			break;
	}
	 /* localpart and @ */
	if (at && (pos > 1 || str_len(tok->last_word) > 0)) {
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_DOMAIN;
	}

	/* localpart, @ not included yet */
	if (pos > 0 && (IS_ATEXT(*(p-1)) || *(p-1) == '.')) {
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return  EMAIL_ADDRESS_PARSER_STATE_LOCALPART;
	}
	/* not a localpart. skip past rest of no-good chars. */
	pos += skip_nonlocal_part(p, size - pos);
	*skip_r = pos;
	return EMAIL_ADDRESS_PARSER_STATE_NONE;
}

/* TODO:  might be  nice  if error  was  -1, but  that  requires a  _r
   param */
static size_t chars_after_at(struct email_address_fts_tokenizer *tok)
{

	size_t len = 0;
	const unsigned char *at;
	const unsigned char *str;

	str = buffer_get_data(tok->last_word, &len);
	at = memchr(str, '@', len);
	if (at == NULL)
		return 0;
	return at - str;
}

/* TODO:
 - allow address literals
 - reject "@..."
 - reject "@.host.tld"
*/
static enum email_address_parser_state
fts_tokenizer_email_address_parse_domain(struct email_address_fts_tokenizer *tok,
                                         const unsigned char *data, size_t size,
                                         size_t *skip_r)
{
	size_t pos = 0;
	const unsigned char *p = data;

	while (pos < size && (IS_DTEXT(*p) || *p == '.')) {
		pos++;
		p++;
	}
	 /* A complete domain name */
	if ((pos > 1 && pos < size) || /* non-atext after atext in this data*/
	    (pos < size && chars_after_at(tok) > 0)) { /* non-atext after previous atext */
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_COMPLETE;
	}
	if (pos == size) { /* All good, but possibly not complete. */
		str_append_n(tok->last_word, data, pos);
		*skip_r = pos;
		return EMAIL_ADDRESS_PARSER_STATE_DOMAIN;
	}
	/* not a domain. skip past no-good chars. */
	pos += skip_nonlocal_part(p, size - pos);
	*skip_r = pos;
	return EMAIL_ADDRESS_PARSER_STATE_NONE;
}

/* Buffer raw data for parent. */
static void
fts_tokenizer_address_update_parent(struct email_address_fts_tokenizer *tok,
                                    const unsigned char *data, size_t size)
{
	if (!tok->no_parent)
		str_append_n(tok->parent_data, data, size);
}
static int
fts_tokenizer_email_address_next(struct fts_tokenizer *_tok,
                                 const unsigned char *data, size_t size,
                                 size_t *skip_r, const char **token_r)
{
	struct email_address_fts_tokenizer *tok =
		(struct email_address_fts_tokenizer *)_tok;
	size_t pos = 0, local_skip;

	if (tok->tokenizer.skip_parents == TRUE)
		tok->tokenizer.skip_parents = FALSE;

	if (tok->state == EMAIL_ADDRESS_PARSER_STATE_COMPLETE) {
		*skip_r = pos;
		return fts_tokenizer_address_current_token(tok, token_r);
	}

	/* end of data, output lingering tokens. first the parents data, then
	   possibly our token, if complete enough */
	if (size == 0) {
		if (!tok->no_parent && str_len(tok->parent_data) > 0)
			return fts_tokenizer_address_parent_data(tok, token_r);

		if (tok->state == EMAIL_ADDRESS_PARSER_STATE_DOMAIN
		    && chars_after_at(tok) > 0)
			return fts_tokenizer_address_current_token(tok, token_r);
	}

	/* 1) regular input data OR
	   2) circle around to return completed address */
	while(pos < size || tok->state == EMAIL_ADDRESS_PARSER_STATE_COMPLETE) {

		switch (tok->state) {
		case EMAIL_ADDRESS_PARSER_STATE_NONE:
			/* no part of address found yet. remove possible
			   earlier data */
			str_truncate(tok->last_word, 0);

			/* fall through */
		case EMAIL_ADDRESS_PARSER_STATE_LOCALPART:
			/* last_word is empty or has the beginnings of a valid
			   local-part, but no '@' found yet. continue parsing
			   the beginning of data to see if it contains a full
			   local-part@ */
			tok->state =
				fts_tokenizer_email_address_parse_local(tok,
				                                        data + pos,
				                                        size - pos,
				                                        &local_skip);
			fts_tokenizer_address_update_parent(tok, data+pos,
			                                    local_skip);
			pos += local_skip;

			break;
		case EMAIL_ADDRESS_PARSER_STATE_DOMAIN:
			/* last_word has a local-part@ and maybe the beginning
			   of a domain. continue parsing the beginning of data
			   to see if it contains a valid domain. */

			tok->state =
				fts_tokenizer_email_address_parse_domain(tok,
				                                        data + pos,
				                                        size - pos,
				                                        &local_skip);
			fts_tokenizer_address_update_parent(tok, data+pos,
			                                    local_skip);
			pos += local_skip;

			break;
		case EMAIL_ADDRESS_PARSER_STATE_COMPLETE:
			/* skip tailing non-atext */
			local_skip = skip_nonlocal_part(data+pos, size - pos);
			*skip_r = pos + local_skip;
			fts_tokenizer_address_update_parent(tok, data+pos,
			                                    local_skip);
			if (!tok->no_parent)
				return fts_tokenizer_address_parent_data(tok, token_r);
			else {
				return fts_tokenizer_address_current_token(tok, token_r);
			}
		default:
			i_unreached();
		}

	}
	*skip_r = pos;
	return 0;
}

static const struct fts_tokenizer_vfuncs email_address_tokenizer_vfuncs = {
	fts_tokenizer_email_address_create,
	fts_tokenizer_email_address_destroy,
	fts_tokenizer_email_address_next
};

static const struct fts_tokenizer fts_tokenizer_email_address_real = {
	.name = FTS_TOKENIZER_EMAIL_ADDRESS_NAME,
	.v = &email_address_tokenizer_vfuncs
};
const struct fts_tokenizer *fts_tokenizer_email_address =
	&fts_tokenizer_email_address_real;
