#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

/*
 * Character definitions
 */

extern const unsigned char _http_token_char_mask;
extern const unsigned char _http_value_char_mask;
extern const unsigned char _http_text_char_mask;
extern const unsigned char _http_qdtext_char_mask;
extern const unsigned char _http_ctext_char_mask;

extern const unsigned char _http_char_lookup[256];

static inline bool http_char_is_token(unsigned char ch) {
	return (_http_char_lookup[ch] & _http_token_char_mask) != 0;
}

static inline bool http_char_is_value(unsigned char ch) {
	return (_http_char_lookup[ch] & _http_value_char_mask) != 0;
}

static inline bool http_char_is_text(unsigned char ch) {
	return (_http_char_lookup[ch] & _http_text_char_mask) != 0;
}

static inline bool http_char_is_qdtext(unsigned char ch) {
	return (_http_char_lookup[ch] & _http_qdtext_char_mask) != 0;
}

static inline bool http_char_is_ctext(unsigned char ch) {
	return (_http_char_lookup[ch] & _http_ctext_char_mask) != 0;
}

/*
 * HTTP value parsing
 */

struct http_parser {
	const unsigned char *begin, *cur, *end;
};

void http_parser_init(struct http_parser *parser,
			const unsigned char *data, size_t size);

void http_parse_ows(struct http_parser *parser);

int http_parse_token(struct http_parser *parser, const char **token_r);
int http_parse_token_list_next(struct http_parser *parser,
	const char **token_r);

#endif
