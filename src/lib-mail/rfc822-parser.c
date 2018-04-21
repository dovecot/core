/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "rfc822-parser.h"

/*
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

void rfc822_parser_init(struct rfc822_parser_context *ctx,
			const unsigned char *data, size_t size,
			string_t *last_comment)
{
	i_zero(ctx);
	ctx->data = data;
	ctx->end = data + size;
	ctx->last_comment = last_comment;
}

int rfc822_skip_comment(struct rfc822_parser_context *ctx)
{
	const unsigned char *start;
	int level = 1;

	i_assert(*ctx->data == '(');

	if (ctx->last_comment != NULL)
		str_truncate(ctx->last_comment, 0);

	start = ++ctx->data;
	for (; ctx->data < ctx->end; ctx->data++) {
		switch (*ctx->data) {
		case '(':
			level++;
			break;
		case ')':
			if (--level == 0) {
				if (ctx->last_comment != NULL) {
					str_append_data(ctx->last_comment, start,
							ctx->data - start);
				}
				ctx->data++;
				return ctx->data < ctx->end ? 1 : 0;
			}
			break;
		case '\\':
			if (ctx->last_comment != NULL) {
				str_append_data(ctx->last_comment, start,
						ctx->data - start);
			}
			start = ctx->data + 1;

			ctx->data++;
			if (ctx->data >= ctx->end)
				return -1;
			break;
		}
	}

	/* missing ')' */
	return -1;
}

int rfc822_skip_lwsp(struct rfc822_parser_context *ctx)
{
	for (; ctx->data < ctx->end;) {
		if (*ctx->data == ' ' || *ctx->data == '\t' ||
		    *ctx->data == '\r' || *ctx->data == '\n') {
                        ctx->data++;
			continue;
		}

		if (*ctx->data != '(')
			break;

		if (rfc822_skip_comment(ctx) < 0)
			return -1;
	}
	return ctx->data < ctx->end ? 1 : 0;
}

int rfc822_parse_atom(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;

	/*
	   atom            = [CFWS] 1*atext [CFWS]
	   atext           =
	     ; Any character except controls, SP, and specials.
	*/
	if (ctx->data >= ctx->end || !IS_ATEXT(*ctx->data))
		return -1;

	for (start = ctx->data++; ctx->data < ctx->end; ctx->data++) {
		if (IS_ATEXT(*ctx->data))
			continue;

		str_append_n(str, start, ctx->data - start);
		return rfc822_skip_lwsp(ctx);
	}

	str_append_n(str, start, ctx->data - start);
	return 0;
}

int rfc822_parse_dot_atom(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;
	int ret;

	/*
	   dot-atom        = [CFWS] dot-atom-text [CFWS]
	   dot-atom-text   = 1*atext *("." 1*atext)

	   atext           =
	     ; Any character except controls, SP, and specials.

	   For RFC-822 compatibility allow LWSP around '.'
	*/
	if (ctx->data >= ctx->end || !IS_ATEXT(*ctx->data))
		return -1;

	for (start = ctx->data++; ctx->data < ctx->end; ) {
		if (IS_ATEXT(*ctx->data)) {
			ctx->data++;
			continue;
		}

		str_append_n(str, start, ctx->data - start);

		if ((ret = rfc822_skip_lwsp(ctx)) <= 0)
			return ret;

		if (*ctx->data != '.')
			return 1;

		ctx->data++;
		str_append_c(str, '.');

		if ((ret = rfc822_skip_lwsp(ctx)) <= 0)
			return ret;
		start = ctx->data;
	}

	str_append_n(str, start, ctx->data - start);
	return 0;
}

int rfc822_parse_mime_token(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;

	for (start = ctx->data; ctx->data < ctx->end; ctx->data++) {
		if (IS_ATEXT_NON_TSPECIAL(*ctx->data) || *ctx->data == '.')
			continue;

		str_append_n(str, start, ctx->data - start);
		return rfc822_skip_lwsp(ctx);
	}

	str_append_n(str, start, ctx->data - start);
	return 0;
}

int rfc822_parse_quoted_string(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;
	size_t len;

	i_assert(ctx->data < ctx->end);
	i_assert(*ctx->data == '"');
	ctx->data++;

	for (start = ctx->data; ctx->data < ctx->end; ctx->data++) {
		switch (*ctx->data) {
		case '"':
			str_append_data(str, start, ctx->data - start);
			ctx->data++;
			return rfc822_skip_lwsp(ctx);
		case '\n':
			/* folding whitespace, remove the (CR)LF */
			len = ctx->data - start;
			if (len > 0 && start[len-1] == '\r')
				len--;
			str_append_data(str, start, len);
			start = ctx->data + 1;
			break;
		case '\\':
			ctx->data++;
			if (ctx->data >= ctx->end)
				return -1;

			str_append_data(str, start, ctx->data - start - 1);
			start = ctx->data;
			break;
		}
	}

	/* missing '"' */
	return -1;
}

static int
rfc822_parse_atom_or_dot(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;

	/*
	   atom            = [CFWS] 1*atext [CFWS]
	   atext           =
	     ; Any character except controls, SP, and specials.

	   The difference between this function and rfc822_parse_dot_atom()
	   is that this doesn't just silently skip over all the whitespace.
	*/
	for (start = ctx->data; ctx->data < ctx->end; ctx->data++) {
		if (IS_ATEXT(*ctx->data) || *ctx->data == '.')
			continue;

		str_append_n(str, start, ctx->data - start);
		return rfc822_skip_lwsp(ctx);
	}

	str_append_n(str, start, ctx->data - start);
	return 0;
}

int rfc822_parse_phrase(struct rfc822_parser_context *ctx, string_t *str)
{
	int ret;

	/*
	   phrase     = 1*word / obs-phrase
	   word       = atom / quoted-string
	   obs-phrase = word *(word / "." / CFWS)
	*/

	if (ctx->data >= ctx->end)
		return 0;
	if (*ctx->data == '.')
		return -1;

	for (;;) {
		if (*ctx->data == '"')
			ret = rfc822_parse_quoted_string(ctx, str);
		else
			ret = rfc822_parse_atom_or_dot(ctx, str);

		if (ret <= 0)
			return ret;

		if (!IS_ATEXT(*ctx->data) && *ctx->data != '"'
		    && *ctx->data != '.')
			break;
		str_append_c(str, ' ');
	}
	return rfc822_skip_lwsp(ctx);
}

static int
rfc822_parse_domain_literal(struct rfc822_parser_context *ctx, string_t *str)
{
	const unsigned char *start;

	/*
	   domain-literal  = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
	   dcontent        = dtext / quoted-pair
	   dtext           = NO-WS-CTL /     ; Non white space controls
			     %d33-90 /       ; The rest of the US-ASCII
			     %d94-126        ;  characters not including "[",
					     ;  "]", or "\"
	*/
	i_assert(ctx->data < ctx->end);
	i_assert(*ctx->data == '[');

	for (start = ctx->data; ctx->data < ctx->end; ctx->data++) {
		if (*ctx->data == '\\') {
			ctx->data++;
			if (ctx->data >= ctx->end)
				break;
		} else if (*ctx->data == ']') {
			ctx->data++;
			str_append_data(str, start, ctx->data - start);
			return rfc822_skip_lwsp(ctx);
		}
	}

	/* missing ']' */
	return -1;
}

int rfc822_parse_domain(struct rfc822_parser_context *ctx, string_t *str)
{
	/*
	   domain          = dot-atom / domain-literal / obs-domain
	   domain-literal  = [CFWS] "[" *([FWS] dcontent) [FWS] "]" [CFWS]
	   obs-domain      = atom *("." atom)
	*/
	i_assert(ctx->data < ctx->end);
	i_assert(*ctx->data == '@');
	ctx->data++;

	if (rfc822_skip_lwsp(ctx) <= 0)
		return -1;

	if (*ctx->data == '[')
		return rfc822_parse_domain_literal(ctx, str);
	else
		return rfc822_parse_dot_atom(ctx, str);
}

int rfc822_parse_content_type(struct rfc822_parser_context *ctx, string_t *str)
{
	if (rfc822_skip_lwsp(ctx) <= 0)
		return -1;

	/* get main type */
	if (rfc822_parse_mime_token(ctx, str) <= 0)
		return -1;

	/* skip over "/" */
	if (*ctx->data != '/')
		return -1;
	ctx->data++;
	if (rfc822_skip_lwsp(ctx) <= 0)
		return -1;
	str_append_c(str, '/');

	/* get subtype */
	return rfc822_parse_mime_token(ctx, str);
}

int rfc822_parse_content_param(struct rfc822_parser_context *ctx,
			       const char **key_r, string_t *value)
{
	string_t *key;
	int ret;

	/* .. := *(";" parameter)
	   parameter := attribute "=" value
	   attribute := token
	   value := token / quoted-string
	*/
	*key_r = NULL;
	str_truncate(value, 0);

	if (ctx->data >= ctx->end)
		return 0;
	if (*ctx->data != ';')
		return -1;
	ctx->data++;

	if (rfc822_skip_lwsp(ctx) <= 0)
		return -1;

	key = t_str_new(64);
	if (rfc822_parse_mime_token(ctx, key) <= 0)
		return -1;

	if (*ctx->data != '=')
		return -1;
	ctx->data++;

	if ((ret = rfc822_skip_lwsp(ctx)) <= 0) {
		/* broken / no value */
	} else if (*ctx->data == '"') {
		ret = rfc822_parse_quoted_string(ctx, value);
	} else if (ctx->data < ctx->end && *ctx->data == '=') {
		/* workaround for broken input:
		   name==?utf-8?b?...?= */
		while (ctx->data < ctx->end && *ctx->data != ';' &&
		       *ctx->data != ' ' && *ctx->data != '\t' &&
		       *ctx->data != '\r' && *ctx->data != '\n') {
			str_append_c(value, *ctx->data);
			ctx->data++;
		}
	} else {
		ret = rfc822_parse_mime_token(ctx, value);
	}

	*key_r = str_c(key);
	return ret < 0 ? -1 : 1;
}
