#ifndef __RFC822_PARSER_H
#define __RFC822_PARSER_H

struct rfc822_parser_context {
	const unsigned char *data, *end;
	string_t *last_comment;
};

void rfc822_parser_init(struct rfc822_parser_context *ctx,
			const unsigned char *data, size_t size,
			string_t *last_comment);

/* Parse comment. Assumes parser's data points to '(' */
int rfc822_skip_comment(struct rfc822_parser_context *ctx);
/* Skip LWSP if there is any */
int rfc822_skip_lwsp(struct rfc822_parser_context *ctx);
/* Stop at next non-atext char */
int rfc822_parse_atom(struct rfc822_parser_context *ctx, string_t *str);
/* Like parse_atom() but don't stop at '.' */
int rfc822_parse_dot_atom(struct rfc822_parser_context *ctx, string_t *str);
/* Like parse_dot_atom() but stops for '/', '?' and '='.
   Also it doesn't allow LWSP around '.' chars. */
int rfc822_parse_mime_token(struct rfc822_parser_context *ctx, string_t *str);
/* "quoted string" */
int rfc822_parse_quoted_string(struct rfc822_parser_context *ctx,
			       string_t *str);
/* atom or quoted-string */
int rfc822_parse_phrase(struct rfc822_parser_context *ctx, string_t *str);
/* dot-atom / domain-literal */
int rfc822_parse_domain(struct rfc822_parser_context *ctx, string_t *str);

#endif
