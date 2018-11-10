#ifndef SMTP_SYNTAX_H
#define SMTP_SYNTAX_H

struct smtp_parser;

/*
 * String
 */

int smtp_string_parse(const char *string,
	const char **value_r, const char **error_r);
void smtp_string_write(string_t *out, const char *value);

/*
 * Xtext encoding
 */

int smtp_xtext_parse(const char *xtext,
	const char **value_r, const char **error_r);

void smtp_xtext_encode(string_t *out,
	const unsigned char *data, size_t size);
static inline void
smtp_xtext_encode_cstr(string_t *out, const char *data)
{
	smtp_xtext_encode(out,
		(const unsigned char *)data, strlen(data));
}

/*
 * HELO domain
 */

int smtp_helo_domain_parse(const char *helo,
	bool allow_literal, const char **domain_r);

/*
 * EHLO reply
 */

bool smtp_ehlo_keyword_is_valid(const char *keyword);
bool smtp_ehlo_param_is_valid(const char *param);
bool smtp_ehlo_params_str_is_valid(const char *params);

int smtp_ehlo_line_parse(const char *ehlo_line,
	const char **key_r, const char *const **params_r,
	const char **error_r);

#endif
