/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "message-tokenize.h"

struct message_tokenizer {
	const unsigned char *data;
	size_t size;

	message_tokenize_error_callback_t error_cb;
	void *error_context;

	int token;
	size_t token_pos, token_len;
	size_t parse_pos;

	unsigned int skip_comments:1;
	unsigned int dot_token:1;

	unsigned int in_bracket:1;
};

#define PARSE_ERROR() \
	STMT_START { \
	if (tok->error_cb != NULL && \
	    !tok->error_cb(data, i, '\0', tok->error_context)) { \
		tok->token = TOKEN_LAST; \
		return TOKEN_LAST; \
	} \
	} STMT_END

#define PARSE_ERROR_MISSING(c) \
	STMT_START { \
	if (tok->error_cb != NULL && \
	    !tok->error_cb(data, i, c, tok->error_context)) { \
		tok->token = TOKEN_LAST; \
		return TOKEN_LAST; \
	} \
	} STMT_END


struct message_tokenizer *
message_tokenize_init(const unsigned char *data, size_t size,
		      message_tokenize_error_callback_t error_cb,
		      void *error_context)
{
	struct message_tokenizer *tok;

	tok = i_new(struct message_tokenizer, 1);
	tok->data = data;
	tok->size = size;

	tok->error_cb = error_cb;
	tok->error_context = error_context;

	tok->skip_comments = TRUE;
	tok->dot_token = TRUE;

	tok->token = -1;
	return tok;
}

void message_tokenize_deinit(struct message_tokenizer *tok)
{
	i_free(tok);
}

void message_tokenize_skip_comments(struct message_tokenizer *tok, int set)
{
	tok->skip_comments = set;
}

void message_tokenize_dot_token(struct message_tokenizer *tok, int set)
{
	tok->dot_token = set;
}

enum message_token message_tokenize_next(struct message_tokenizer *tok)
{
	int token, level, last_atom;
	const unsigned char *data;
	size_t i, size;

	if (tok->token == TOKEN_LAST)
		return TOKEN_LAST;

	data = tok->data;
	size = tok->size;

	tok->token = TOKEN_LAST;

	last_atom = FALSE;
	for (i = tok->parse_pos; i < size && data[i] != '\0'; i++) {
		token = -1;
		switch (data[i]) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			/* skip whitespace */
			break;

		case '(':
			/* (comment) - nesting is allowed */
			if (last_atom)
				break;

			token = '(';
			tok->token_pos = ++i;

			level = 1;
			for (; i < size && data[i] != '\0'; i++) {
				if (data[i] == '\\' &&
				    i+1 < size && data[i+1] != '\0')
					i++;
				else if (data[i] == '(')
					level++;
				else if (data[i] == ')') {
					if (--level == 0)
						break;
				}
			}

			if (level > 0)
				PARSE_ERROR_MISSING(')');

			tok->token_len = (size_t) (i - tok->token_pos);
			break;

		case '[':
			/* domain literal - nesting isn't allowed */
			if (last_atom)
				break;

			token = '[';
			tok->token_pos = ++i;

			while (i < size && data[i] != '\0' && data[i] != ']') {
				if (data[i] == '\\' &&
				    i+1 < size && data[i+1] != '\0')
					i++;
				else if (data[i] == '[') {
					/* nesting not allowed, but
					   continue anyway */
					PARSE_ERROR();
				}

				i++;
			}

			if (i == size || data[i] == '\0')
				PARSE_ERROR_MISSING(']');

			tok->token_len = (size_t) (i - tok->token_pos);
			break;

		case '"':
			/* quoted string */
			if (last_atom)
				break;

			token = '"';
			tok->token_pos = ++i;

			while (i < size && data[i] != '\0' && data[i] != '"') {
				if (data[i] == '\\' &&
				    i+1 < size && data[i+1] != '\0')
					i++;
				i++;
			}

			if (i == size || data[i] == '\0')
				PARSE_ERROR_MISSING('"');

			tok->token_len = (size_t) (i - tok->token_pos);
			break;

		case '<':
			if (last_atom)
				break;

			if (tok->in_bracket) {
				/* '<' cannot be nested */
				PARSE_ERROR();
			}

			token = '<';
			tok->in_bracket = TRUE;
			break;
		case '>':
			if (last_atom)
				break;

			if (!tok->in_bracket) {
				/* missing '<' */
                                PARSE_ERROR();
			}

			token = '>';
			tok->in_bracket = FALSE;
			break;

		case ')':
		case ']':
		case '\\':
			PARSE_ERROR();
			/* fall through */

		/* RFC822 specials: */
		case '@':
		case ',':
		case ';':
		case ':':
		case '.':
		/* RFC 2045 specials: */
		case '/':
		case '?':
		case '=':
			token = tok->data[i];
			if (token != '.' || tok->dot_token)
				break;
			/* fall through */
		default:
			/* atom */
			token = 'A';
			if (!last_atom) {
				tok->token = token;
				tok->token_pos = i;
				last_atom = TRUE;
			}
			break;
		}

		if (last_atom) {
			if (token != 'A') {
				/* end of atom */
				tok->token_len = (size_t) (i - tok->token_pos);
				last_atom = FALSE;
				break;
			}
		} else {
			if (token != -1) {
				tok->token = token;
				if (i < tok->size && data[i] != '\0')
					i++;
				break;
			}
		}

		if (i == tok->size || data[i] == '\0') {
			/* unexpected eol */
			break;
		}
	}

	if (last_atom) {
		/* end of atom */
		tok->token_len = (size_t) (i - tok->token_pos);
	}

	tok->parse_pos = i;

	if (tok->token == TOKEN_LAST && tok->in_bracket &&
	    tok->error_cb != NULL) {
		if (tok->error_cb(data, i, '>', tok->error_context))
			tok->token = TOKEN_LAST;
	}

	return tok->token;
}

enum message_token message_tokenize_get(const struct message_tokenizer *tok)
{
	return tok->token;
}

size_t message_tokenize_get_parse_position(const struct message_tokenizer *tok)
{
	return tok->parse_pos;
}

const unsigned char *
message_tokenize_get_value(const struct message_tokenizer *tok, size_t *len)
{
	i_assert(IS_TOKEN_STRING(tok->token));

	*len = tok->token_len;
	return tok->data + tok->token_pos;
}

void message_tokenize_get_string(struct message_tokenizer *tok,
				 string_t *str, string_t *comments,
				 const enum message_token *stop_tokens)
{
	enum message_token token;
	const unsigned char *value;
	size_t len;
	int i, token_str, last_str;

	last_str = FALSE;
	while ((token = message_tokenize_next(tok)) != TOKEN_LAST) {
		for (i = 0; stop_tokens[i] != TOKEN_LAST; i++)
			if (token == stop_tokens[i])
				return;

		if (token == TOKEN_COMMENT) {
			/* handle comment specially */
			if (comments != NULL) {
				if (str_len(comments) > 0)
					str_append_c(comments, ' ');

				value = message_tokenize_get_value(tok, &len);
				str_append_unescaped(comments, value, len);
			}
			continue;
		}

		token_str = token == TOKEN_ATOM || token == TOKEN_QSTRING ||
			token == TOKEN_DLITERAL || token == TOKEN_COMMENT;

		if (!token_str)
			str_append_c(str, token);
		else if (token == TOKEN_QSTRING) {
			/* unescape only quoted strings, since we're removing
			   the quotes. for domain literals I don't see much
			   point in unescaping if [] is still kept.. */
			if (last_str)
				str_append_c(str, ' ');

			value = message_tokenize_get_value(tok, &len);
			str_append_unescaped(str, value, len);
		} else {
			if (last_str)
				str_append_c(str, ' ');

			if (token == TOKEN_DLITERAL)
				str_append_c(str, '[');

			value = message_tokenize_get_value(tok, &len);
			str_append_n(str, value, len);

			if (token == TOKEN_DLITERAL)
				str_append_c(str, ']');
		}

		last_str = token_str;
	}
}
