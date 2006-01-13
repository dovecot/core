/* Copyright (C) 2002-2005 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "rfc822-parser.h"
#include "message-content-parser.h"

void message_content_parse_header(const unsigned char *data, size_t size,
				  parse_content_callback_t *callback,
				  parse_content_param_callback_t *param_cb,
				  void *context)
{
	struct rfc822_parser_context parser;
	string_t *str;
	size_t key_len;
	bool quoted_string;

	rfc822_parser_init(&parser, data, size, NULL);

	t_push();
	str = t_str_new(256);

	/* get content type */
        (void)rfc822_skip_lwsp(&parser);
	if (rfc822_parse_mime_token(&parser, str) > 0) {
		if (*parser.data == '/') {
			parser.data++;
			str_append_c(str, '/');
			(void)rfc822_parse_mime_token(&parser, str);
		}
	}

	if (callback != NULL)
		callback(str_data(str), str_len(str), context);

	if (param_cb == NULL) {
		/* we don't care about parameters */
		t_pop();
		return;
	}

	while (parser.data != parser.end && *parser.data == ';') {
		parser.data++;
		(void)rfc822_skip_lwsp(&parser);

		str_truncate(str, 0);
		if (rfc822_parse_mime_token(&parser, str) <= 0)
			break;

		/* <token> "=" <token> | <quoted-string> */
		if (str_len(str) == 0 || *parser.data != '=' ||
		    rfc822_skip_lwsp(&parser) <= 0)
			break;
		parser.data++;

		quoted_string = parser.data != parser.end &&
			*parser.data == '"';
		key_len = str_len(str);
		if (quoted_string) {
			if (rfc822_parse_quoted_string(&parser, str) < 0)
				break;
		} else {
			if (rfc822_parse_mime_token(&parser, str) < 0)
				break;
		}

		param_cb(str_data(str), key_len,
			 str_data(str) + key_len, str_len(str) - key_len,
			 quoted_string, context);

		str_truncate(str, 0);
	}
	t_pop();
}
