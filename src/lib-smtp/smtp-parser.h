#ifndef SMTP_PARSER_H
#define SMTP_PARSER_H

/*
 * Character definitions
 */

extern const uint16_t smtp_xtext_char_mask;
extern const uint16_t smtp_atext_char_mask;
extern const uint16_t smtp_dcontent_char_mask;
extern const uint16_t smtp_qtext_char_mask;
extern const uint16_t smtp_textstr_char_mask;
extern const uint16_t smtp_esmtp_value_char_mask;
extern const uint16_t smtp_ehlo_param_char_mask;
extern const uint16_t smtp_ehlo_greet_char_mask;
extern const uint16_t smtp_qpair_char_mask;

extern const uint16_t smtp_char_lookup[256];

static inline bool
smtp_char_is_xtext(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_xtext_char_mask) != 0;
}
static inline bool
smtp_char_is_atext(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_atext_char_mask) != 0;
}
static inline bool
smtp_char_is_dcontent(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_dcontent_char_mask) != 0;
}
static inline bool
smtp_char_is_qtext(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_qtext_char_mask) != 0;
}
static inline bool
smtp_char_is_textstr(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_textstr_char_mask) != 0;
}
static inline bool
smtp_char_is_esmtp_value(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_esmtp_value_char_mask) != 0;
}
static inline bool
smtp_char_is_ehlo_param(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_ehlo_param_char_mask) != 0;
}
static inline bool
smtp_char_is_ehlo_greet(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_ehlo_greet_char_mask) != 0;
}
static inline bool
smtp_char_is_qpair(unsigned char ch) {
	return (smtp_char_lookup[ch] & smtp_qpair_char_mask) != 0;
}

/*
 * SMTP parser
 */

struct smtp_parser {
	pool_t pool;
	const char *error;

	const unsigned char *begin, *cur, *end;
};

void smtp_parser_init(struct smtp_parser *parser,
	pool_t pool, const char *data);
string_t *smtp_parser_get_tmpbuf(struct smtp_parser *parser, size_t size);

/*
 * Common syntax
 */

int smtp_parser_parse_domain(struct smtp_parser *parser,
	const char **value_r);
int smtp_parser_parse_address_literal(struct smtp_parser *parser,
	const char **value_r, struct ip_addr *ip_r);
int smtp_parser_parse_atom(struct smtp_parser *parser,
	const char **value_r);
int smtp_parser_parse_quoted_string(struct smtp_parser *parser,
	const char **value_r);
int smtp_parser_parse_string(struct smtp_parser *parser,
	const char **value_r);
int smtp_parser_parse_xtext(struct smtp_parser *parser,
	string_t *out);

#endif
