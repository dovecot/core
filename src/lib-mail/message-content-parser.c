/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "rfc822-tokenize.h"
#include "message-content-parser.h"

void message_content_parse_header(const char *data, size_t size,
				  ParseContentFunc func,
				  ParseContentParamFunc param_func,
				  void *context)
{
	static const Rfc822Token stop_tokens[] = { ';', TOKEN_LAST };
	Rfc822TokenizeContext *ctx;
	Rfc822Token token;
	String *str;
	const char *key, *value;
	size_t key_len, value_len;

	ctx = rfc822_tokenize_init(data, size, NULL, NULL);
        rfc822_tokenize_dot_token(ctx, FALSE);

	t_push();
	str = t_str_new(256);

        /* first ';' separates the parameters */
	rfc822_tokenize_get_string(ctx, str, NULL, stop_tokens);

	if (func != NULL)
		func(str_c(str), str_len(str), context);

	t_pop();

	if (param_func != NULL && rfc822_tokenize_get(ctx) == ';') {
		/* parse the parameters */
		while ((token = rfc822_tokenize_next(ctx)) != TOKEN_LAST) {
			/* <token> "=" <token> | <quoted-string> */
			if (token != TOKEN_ATOM)
				continue;

			key = rfc822_tokenize_get_value(ctx, &key_len);

			if (rfc822_tokenize_next(ctx) != '=')
				continue;

			token = rfc822_tokenize_next(ctx);
			if (token != TOKEN_ATOM && token != TOKEN_QSTRING)
				continue;

			value = rfc822_tokenize_get_value(ctx, &value_len);
			param_func(key, key_len, value, value_len,
				   token == TOKEN_QSTRING, context);
		}
	}

	rfc822_tokenize_deinit(ctx);
}
