#ifndef SMTP_REPLY_PARSER_H
#define SMTP_REPLY_PARSER_H

#include "smtp-reply.h"

struct smtp_reply_parser;

bool smtp_reply_parse_enhanced_code(const char *text,
				    struct smtp_reply_enhanced_code *enh_code_r,
				    const char **pos_r) ATTR_NULL(3);

struct smtp_reply_parser *
smtp_reply_parser_init(struct istream *input, size_t max_reply_size);
void smtp_reply_parser_deinit(struct smtp_reply_parser **_parser);

void smtp_reply_parser_set_stream(struct smtp_reply_parser *parser,
				  struct istream *input);

int smtp_reply_parse_next(struct smtp_reply_parser *parser,
			  bool enhanced_codes, struct smtp_reply **reply_r,
			  const char **error_r);
int smtp_reply_parse_ehlo(struct smtp_reply_parser *parser,
			  struct smtp_reply **reply_r, const char **error_r);

#endif
