/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "rfc822-tokenize.h"

#define INITIAL_COUNT 4

#define PARSE_ERROR() \
	STMT_START { \
	if (error_func != NULL && \
	    !error_func(str, (int) (p-str), '\0', user_data)) \
		return NULL; \
	} STMT_END

#define PARSE_ERROR_MISSING(c) \
	STMT_START { \
	if (error_func != NULL && \
	    !error_func(str, (int) (p-str), c, user_data)) \
		return NULL; \
	} STMT_END

static Rfc822Token *alloc_token(Rfc822Token **tokens, int *pos, int type)
{
	Rfc822Token *token;

	if (*pos+1 >= INITIAL_COUNT)
		*tokens = t_buffer_reget_type(*tokens, Rfc822Token, *pos + 2);

	token = (*tokens) + *pos;
	(*pos)++;

	token->token = type;
	token->ptr = NULL;
	token->len = 0;
	return token;
}

const Rfc822Token *rfc822_tokenize(const char *str, int *tokens_count,
				   Rfc822TokenizeErrorFunc error_func,
				   void *user_data)
{
	Rfc822Token *first_token, *token;
	const char *p, *last_atom;
	int level, in_bracket, pos;

	first_token = t_buffer_get_type(Rfc822Token, INITIAL_COUNT);
	pos = 0;

	token = NULL;
	last_atom = NULL;

	in_bracket = FALSE;
	for (p = str; *p != '\0'; p++) {
		switch (*p) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			/* skip whitespace */
			break;

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
			token = alloc_token(&first_token, &pos, *p);
			break;

		case '(':
			/* (comment) - nesting is allowed */
			token = alloc_token(&first_token, &pos, '(');
			token->ptr = ++p;

			level = 1;
			for (; *p != '\0'; p++) {
				if (*p == '\\' && p[1] != '\0')
					p++;
				else if (*p == '(')
					level++;
				else if (*p == ')') {
					if (--level == 0)
						break;
				}
			}

			if (level > 0)
				PARSE_ERROR_MISSING(')');

			token->len = (int) (p - token->ptr);
			break;

		case '[':
			/* domain literal - nesting isn't allowed */
			token = alloc_token(&first_token, &pos, '[');
			token->ptr = ++p;

			for (; *p != '\0' && *p != ']'; p++) {
				if (*p == '\\' && p[1] != '\0')
					p++;
				else if (*p == '[') {
					/* nesting not allowed, but
					   continue anyway */
					PARSE_ERROR();
				}
			}
			token->len = (int) (p - token->ptr);

			if (*p == '\0')
				PARSE_ERROR_MISSING(']');
			break;

		case '"':
			/* quoted string */
			token = alloc_token(&first_token, &pos, '"');
			token->ptr = ++p;

			for (; *p != '\0' && *p != '"'; p++) {
				if (*p == '\\' && p[1] != '\0')
					p++;
			}
			token->len = (int) (p - token->ptr);

			if (*p == '\0')
				PARSE_ERROR_MISSING('"');
			break;

		case '<':
			if (in_bracket) {
				/* '<' cannot be nested */
				PARSE_ERROR();
				break;
			}

			token = alloc_token(&first_token, &pos, '<');
			in_bracket = TRUE;
			break;
		case '>':
			if (!in_bracket) {
				/* missing '<' */
                                PARSE_ERROR();
				break;
			}

			token = alloc_token(&first_token, &pos, '>');
			in_bracket = FALSE;
			break;

		case ')':
		case ']':
		case '\\':
                        PARSE_ERROR();
			break;
		default:
			/* atom */
			if (last_atom != p-1) {
				token = alloc_token(&first_token, &pos, 'A');
				token->ptr = p;
			}

			token->len++;
			last_atom = p;
			break;
		}

		if (*p == '\0')
			break;
	}

	if (in_bracket && error_func != NULL) {
		if (!error_func(str, (int) (p-str), '>', user_data))
			return NULL;
	}

	if (tokens_count != NULL)
		*tokens_count = pos;

	first_token[pos++].token = 0;
	t_buffer_alloc(sizeof(Rfc822Token) * pos);
	return first_token;
}

const char *rfc822_tokens_get_value(const Rfc822Token *tokens, int count,
				    int space_separators)
{
	char *buf;
	unsigned int i, len, buf_size;

	if (count <= 0)
		return "";

	buf_size = 256;
	buf = t_buffer_get(buf_size);

	len = 0;
	for (; count > 0; count--, tokens++) {
		if (tokens->token == '(')
			continue; /* skip comments */

		/* +4 == ' ' '[' ']' '\0' */
		if (len + tokens->len+4 >= buf_size) {
			buf_size = nearest_power(buf_size + tokens->len + 3);
			buf = t_buffer_reget(buf, buf_size);
		}

		if (space_separators && len > 0)
			buf[len++] = ' ';

		switch (tokens->token) {
		case '"':
		case '[':
			if (tokens->token == '[')
				buf[len++] = '[';

			/* copy the string removing '\' chars */
			for (i = 0; i < tokens->len; i++) {
				if (tokens->ptr[i] == '\\' && i+1 < tokens->len)
					i++;

				buf[len++] = tokens->ptr[i];
			}

			if (tokens->token == '[')
				buf[len++] = ']';
			break;
		case 'A':
			memcpy(buf+len, tokens->ptr, tokens->len);
			len += tokens->len;
			break;
		default:
			i_assert(tokens->token != 0);
			buf[len++] = (char) tokens->token;
			break;
		}
	}

	buf[len++] = '\0';
        t_buffer_alloc(len);
	return buf;
}

const char *rfc822_tokens_get_value_quoted(const Rfc822Token *tokens,
					   int count, int space_separators)
{
	char *buf;
	unsigned int len, buf_size;

	if (count <= 0)
		return "\"\"";

	buf_size = 256;
	buf = t_buffer_get(buf_size);
	buf[0] = '"'; len = 1;

	for (; count > 0; count--, tokens++) {
		if (tokens->token == '(')
			continue; /* skip comments */

		/* +5 == ' ' '[' ']' '"' '\0' */
		if (len + tokens->len+5 >= buf_size) {
			buf_size = nearest_power(buf_size + tokens->len + 3);
			buf = t_buffer_reget(buf, buf_size);
		}

		if (space_separators && len > 0)
			buf[len++] = ' ';

		switch (tokens->token) {
		case '"':
		case '[':
			if (tokens->token == '[')
				buf[len++] = '[';

			memcpy(buf+len, tokens->ptr, tokens->len);
			len += tokens->len;

			if (tokens->token == '[')
				buf[len++] = ']';
			break;
		case 'A':
			memcpy(buf+len, tokens->ptr, tokens->len);
			len += tokens->len;
			break;
		default:
			i_assert(tokens->token != 0);
			buf[len++] = (char) tokens->token;
			break;
		}
	}

	buf[len++] = '"';
	buf[len++] = '\0';
        t_buffer_alloc(len);
	return buf;
}
