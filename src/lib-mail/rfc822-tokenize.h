#ifndef __RFC822_TOKENIZE_H
#define __RFC822_TOKENIZE_H

#define IS_TOKEN_STRING(token) \
	((token) == TOKEN_ATOM || (token) == TOKEN_QSTRING || \
	 (token) == TOKEN_COMMENT || (token) == TOKEN_DLITERAL)

typedef enum {
	TOKEN_ATOM	= 'A',
	TOKEN_QSTRING	= '"',
	TOKEN_COMMENT	= '(',
	TOKEN_DLITERAL	= '[',

	/* RFC822 specials:

	   '<', '>', '@', ',', ';', ':', '\'
	   '.' (optional)

	   RFC2045 tspecials:

	   '/', '?', '=' */

	TOKEN_LAST	= 0
} Rfc822Token;

typedef struct _Rfc822TokenizeContext Rfc822TokenizeContext;

/* Parsing is aborted if returns FALSE. There's two kinds of errors:

   missing_char == '\0': unexpected character at str[pos]
   missing_char != '\0': missing character */
typedef int (*Rfc822TokenizeErrorFunc)(const unsigned char *str, size_t pos,
				       char missing_char, void *context);

/* Tokenize the string. Returns NULL if string is empty. Memory for
   returned array is allocated from data stack. You don't have to use
   the tokens_count, since last token is always 0. */
Rfc822TokenizeContext *
rfc822_tokenize_init(const unsigned char *data, size_t size,
		     Rfc822TokenizeErrorFunc error_func, void *error_context);
void rfc822_tokenize_deinit(Rfc822TokenizeContext *ctx);

/* Specify whether comments should be silently skipped (default yes). */
void rfc822_tokenize_skip_comments(Rfc822TokenizeContext *ctx, int set);
/* Specify whether '.' should be treated as a separate token (default yes). */
void rfc822_tokenize_dot_token(Rfc822TokenizeContext *ctx, int set);

/* Parse the next token and return it. */
Rfc822Token rfc822_tokenize_next(Rfc822TokenizeContext *ctx);

/* Return the current token. */
Rfc822Token rfc822_tokenize_get(const Rfc822TokenizeContext *ctx);

/* - not including enclosing "", () or []
   - '\' isn't expanded
   - [CR+]LF+LWSP (continued header) isn't removed */
const unsigned char *
rfc822_tokenize_get_value(const Rfc822TokenizeContext *ctx, size_t *len);

/* Read tokens as a string, all quoted strings will be unquoted.
   Reads until stop_token is found. */
void rfc822_tokenize_get_string(Rfc822TokenizeContext *ctx,
				String *str, String *comments,
				const Rfc822Token *stop_tokens);

#endif
