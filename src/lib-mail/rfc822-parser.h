#ifndef __RFC822_PARSER_H
#define __RFC822_PARSER_H

struct rfc822_parser_context {
	const unsigned char *data, *end;
	string_t *last_comment;
};

void rfc822_parser_init(struct rfc822_parser_context *ctx,
			const unsigned char *data, size_t size,
			string_t *last_comment);

int rfc822_skip_comment(struct rfc822_parser_context *ctx);
int rfc822_skip_lwsp(struct rfc822_parser_context *ctx);
int rfc822_parse_atom(struct rfc822_parser_context *ctx, string_t *str);
int rfc822_parse_dot_atom(struct rfc822_parser_context *ctx, string_t *str);
int rfc822_parse_quoted_string(struct rfc822_parser_context *ctx,
			       string_t *str);
int rfc822_parse_phrase(struct rfc822_parser_context *ctx, string_t *str);
int rfc822_parse_domain(struct rfc822_parser_context *ctx, string_t *str);

#endif
