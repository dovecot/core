/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "rfc822-tokenize.h"

struct _Rfc822TokenizeContext {
	const char *data;
	size_t size;

	Rfc822TokenizeErrorFunc error_func;
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
	if (ctx->error_func != NULL && \
	    !ctx->error_func(data, i, '\0', ctx->error_context)) { \
		ctx->token = TOKEN_LAST; \
		return TOKEN_LAST; \
	} \
	} STMT_END

#define PARSE_ERROR_MISSING(c) \
	STMT_START { \
	if (ctx->error_func != NULL && \
	    !ctx->error_func(data, i, c, ctx->error_context)) { \
		ctx->token = TOKEN_LAST; \
		return TOKEN_LAST; \
	} \
	} STMT_END


Rfc822TokenizeContext *
rfc822_tokenize_init(const char *data, size_t size,
		     Rfc822TokenizeErrorFunc error_func, void *error_context)
{
	Rfc822TokenizeContext *ctx;

	ctx = i_new(Rfc822TokenizeContext, 1);
	ctx->data = data;
	ctx->size = size;

	ctx->error_func = error_func;
	ctx->error_context = error_context;

	ctx->skip_comments = TRUE;
	ctx->dot_token = TRUE;

	ctx->token = -1;
	return ctx;
}

void rfc822_tokenize_deinit(Rfc822TokenizeContext *ctx)
{
	i_free(ctx);
}

void rfc822_tokenize_skip_comments(Rfc822TokenizeContext *ctx, int set)
{
	ctx->skip_comments = set;
}

void rfc822_tokenize_dot_token(Rfc822TokenizeContext *ctx, int set)
{
	ctx->dot_token = set;
}

Rfc822Token rfc822_tokenize_next(Rfc822TokenizeContext *ctx)
{
	int token, level, last_atom;
	const char *data;
	size_t i, size;

	if (ctx->token == TOKEN_LAST)
		return TOKEN_LAST;

	data = ctx->data;
	size = ctx->size;

	ctx->token = TOKEN_LAST;

	last_atom = FALSE;
	for (i = ctx->parse_pos; i < size && data[i] != '\0'; i++) {
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
			ctx->token_pos = ++i;

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

			ctx->token_len = (size_t) (i - ctx->token_pos);
			break;

		case '[':
			/* domain literal - nesting isn't allowed */
			if (last_atom)
				break;

			token = '[';
			ctx->token_pos = ++i;

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

			ctx->token_len = (size_t) (i - ctx->token_pos);
			break;

		case '"':
			/* quoted string */
			if (last_atom)
				break;

			token = '"';
			ctx->token_pos = ++i;

			while (i < size && data[i] != '\0' && data[i] != '"') {
				if (data[i] == '\\' &&
				    i+1 < size && data[i+1] != '\0')
					i++;
				i++;
			}

			if (i == size || data[i] == '\0')
				PARSE_ERROR_MISSING('"');

			ctx->token_len = (size_t) (i - ctx->token_pos);
			break;

		case '<':
			if (last_atom)
				break;

			if (ctx->in_bracket) {
				/* '<' cannot be nested */
				PARSE_ERROR();
			}

			token = '<';
			ctx->in_bracket = TRUE;
			break;
		case '>':
			if (last_atom)
				break;

			if (!ctx->in_bracket) {
				/* missing '<' */
                                PARSE_ERROR();
			}

			token = '>';
			ctx->in_bracket = FALSE;
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
			token = ctx->data[i];
			if (token != '.' || ctx->dot_token)
				break;
			/* fall through */
		default:
			/* atom */
			token = 'A';
			if (!last_atom) {
				ctx->token = token;
				ctx->token_pos = i;
				last_atom = TRUE;
			}
			break;
		}

		if (last_atom) {
			if (token != 'A') {
				/* end of atom */
				ctx->token_len = (size_t) (i - ctx->token_pos);
				last_atom = FALSE;
				break;
			}
		} else {
			if (token != -1) {
				ctx->token = token;
				if (i < ctx->size && data[i] != '\0')
					i++;
				break;
			}
		}

		if (i == ctx->size || data[i] == '\0') {
			/* unexpected eol */
			break;
		}
	}

	if (last_atom) {
		/* end of atom */
		ctx->token_len = (size_t) (i - ctx->token_pos);
	}

	ctx->parse_pos = i;

	if (ctx->token == TOKEN_LAST && ctx->in_bracket &&
	    ctx->error_func != NULL) {
		if (ctx->error_func(data, i, '>', ctx->error_context))
			ctx->token = TOKEN_LAST;
	}

	return ctx->token;
}

Rfc822Token rfc822_tokenize_get(const Rfc822TokenizeContext *ctx)
{
	return ctx->token;
}

const char *rfc822_tokenize_get_value(const Rfc822TokenizeContext *ctx,
				      size_t *len)
{
	i_assert(IS_TOKEN_STRING(ctx->token));

	*len = ctx->token_len;
	return ctx->data + ctx->token_pos;
}

void rfc822_tokenize_get_string(Rfc822TokenizeContext *ctx,
				String *str, String *comments,
				const Rfc822Token *stop_tokens)
{
	Rfc822Token token;
	const char *value;
	size_t len;
	int i, token_str, last_str;

	last_str = FALSE;
	while ((token = rfc822_tokenize_next(ctx)) != TOKEN_LAST) {
		for (i = 0; stop_tokens[i] != TOKEN_LAST; i++)
			if (token == stop_tokens[i])
				return;

		if (token == TOKEN_COMMENT) {
			/* handle comment specially */
			if (comments != NULL) {
				if (str_len(comments) > 0)
					str_append_c(comments, ' ');

				value = rfc822_tokenize_get_value(ctx, &len);
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

			value = rfc822_tokenize_get_value(ctx, &len);
			str_append_unescaped(str, value, len);
		} else {
			if (last_str)
				str_append_c(str, ' ');

			if (token == TOKEN_DLITERAL)
				str_append_c(str, '[');

			value = rfc822_tokenize_get_value(ctx, &len);
			str_append_n(str, value, len);

			if (token == TOKEN_DLITERAL)
				str_append_c(str, ']');
		}

		last_str = token_str;
	}
}
