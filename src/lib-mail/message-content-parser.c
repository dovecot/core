/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "rfc822-tokenize.h"
#include "message-content-parser.h"

int message_content_parse_header(const char *value, ParseContentFunc func,
				 ParseContentParamFunc param_func,
				 void *context)
{
	const Rfc822Token *tokens;
	int i, next, ntokens;

	tokens = rfc822_tokenize(value, &ntokens, NULL, NULL);
	if (tokens == NULL) {
		/* error */
		return FALSE;
	}

	/* first ';' separates the parameters */
	for (i = 0; i < ntokens; i++) {
		if (tokens[i].token == ';')
			break;
	}

	if (func != NULL)
		func(tokens, i, context);

	if (param_func != NULL) {
		/* parse the parameters */
		for (i++; i < ntokens; i = next) {
			/* find the next ';' */
			for (next = i+1; next < ntokens; next++) {
				if (tokens[next].token == ';')
					break;
			}

			if (i+2 < next &&
			    tokens[i].token == 'A' &&
			    tokens[i+1].token == '=') {
				/* <atom> = <value> */
				param_func(tokens + i, tokens + i + 2,
					   next - (i+2), context);
			}
		}
	}

	return TRUE;
}
