#ifndef __RFC822_TOKENIZE_H
#define __RFC822_TOKENIZE_H

typedef struct _Rfc822Token Rfc822Token;

#define IS_TOKEN_STRING(token) \
	((token) == 'A' || (token) == '"' || (token) == '(' || (token) == '['))

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t')

struct _Rfc822Token {
	/*
	   0   = last token
	   'A' = atom
	   '"' = quoted string
	   '(' = comment
	   '[' = domain literal

	   RFC822 specials:

	   '<', '>', '@', ',', ';', ':', '\', '.'

	   RFC2045 tspecials:

	   '/', '?', '='
	*/
	int token;

        /* - not including enclosing "", () or []
	   - '\' isn't expanded
	   - [CR+]LF+LWSP (continued header) isn't removed */
	const char *ptr;
	size_t len;
};

/* Parsing is aborted if returns FALSE. There's two kinds of errors:

   missing_char == '\0': unexpected character at str[pos]
   missing_char != '\0': missing character */
typedef int (*Rfc822TokenizeErrorFunc)(const char *str, int pos,
				       char missing_char, void *context);

/* Tokenize the string. Returns NULL if string is empty. Memory for
   returned array is allocated from temporary pool. You don't have to use
   the tokens_count, since last token is always 0. */
const Rfc822Token *rfc822_tokenize(const char *str, int *tokens_count,
				   Rfc822TokenizeErrorFunc error_func,
				   void *context);

/* Returns the tokens as a string. Tokens are merged together, except
   spaces are added between atoms. */
const char *rfc822_tokens_get_value(const Rfc822Token *tokens, int count);
/* Returns the tokens as a "string". */
const char *rfc822_tokens_get_value_quoted(const Rfc822Token *tokens,
					   int count);

#endif
