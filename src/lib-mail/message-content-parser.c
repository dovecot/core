/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "message-tokenize.h"
#include "message-content-parser.h"

void message_content_parse_header(const unsigned char *data, size_t size,
				  ParseContentFunc func,
				  ParseContentParamFunc param_func,
				  void *context)
{
	static const enum message_token stop_tokens[] = { ';', TOKEN_LAST };
	struct message_tokenizer *tok;
	enum message_token token;
	string_t *str;
	const unsigned char *key, *value;
	size_t key_len, value_len;

	tok = message_tokenize_init(data, size, NULL, NULL);
        message_tokenize_dot_token(tok, FALSE);

	t_push();
	str = t_str_new(256);

        /* first ';' separates the parameters */
	message_tokenize_get_string(tok, str, NULL, stop_tokens);

	if (func != NULL)
		func(str_data(str), str_len(str), context);

	t_pop();

	if (param_func != NULL && message_tokenize_get(tok) == ';') {
		/* parse the parameters */
		while ((token = message_tokenize_next(tok)) != TOKEN_LAST) {
			/* <token> "=" <token> | <quoted-string> */
			if (token != TOKEN_ATOM)
				continue;

			key = message_tokenize_get_value(tok, &key_len);

			if (message_tokenize_next(tok) != '=')
				continue;

			token = message_tokenize_next(tok);
			if (token != TOKEN_ATOM && token != TOKEN_QSTRING)
				continue;

			value = message_tokenize_get_value(tok, &value_len);
			param_func(key, key_len, value, value_len,
				   token == TOKEN_QSTRING, context);
		}
	}

	message_tokenize_deinit(tok);
}
