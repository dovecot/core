#ifndef __MESSAGE_TOKENIZE_H
#define __MESSAGE_TOKENIZE_H

#define IS_TOKEN_STRING(token) \
	((token) == TOKEN_ATOM || (token) == TOKEN_QSTRING || \
	 (token) == TOKEN_COMMENT || (token) == TOKEN_DLITERAL)

enum message_token {
	TOKEN_ATOM	= 'A',
	TOKEN_QSTRING	= '"',
	TOKEN_COMMENT	= '(',
	TOKEN_DLITERAL	= '[',

	/* RFC822 specials:

	   '<', '>', '@', ',', ';', ':', '\'
	   '.' (not included in RFC2045 -> optional)

	   RFC2045 tspecials:

	   '/', '?', '=' */

	TOKEN_LAST	= 0
};

struct message_tokenizer;

/* Parsing is aborted if returns FALSE. There's two kinds of errors:

   missing_char == '\0': unexpected character at str[pos]
   missing_char != '\0': missing character */
typedef int (*MessageTokenizeErrorFunc)(const unsigned char *str, size_t pos,
					char missing_char, void *context);

/* Tokenize the string. Returns NULL if string is empty. Memory for
   returned array is allocated from data stack. You don't have to use
   the tokens_count, since last token is always 0. */
struct message_tokenizer *
message_tokenize_init(const unsigned char *data, size_t size,
		      MessageTokenizeErrorFunc error_func, void *error_context);
void message_tokenize_deinit(struct message_tokenizer *tok);

/* Specify whether comments should be silently skipped (default yes). */
void message_tokenize_skip_comments(struct message_tokenizer *tok, int set);
/* Specify whether '.' should be treated as a separate token (default yes). */
void message_tokenize_dot_token(struct message_tokenizer *tok, int set);

/* Parse the next token and return it. */
enum message_token message_tokenize_next(struct message_tokenizer *tok);

/* Return the current token. */
enum message_token message_tokenize_get(const struct message_tokenizer *tok);

/* - not including enclosing "", () or []
   - '\' isn't expanded
   - [CR+]LF+LWSP (continued header) isn't removed */
const unsigned char *
message_tokenize_get_value(const struct message_tokenizer *tok, size_t *len);

/* Read tokens as a string, all quoted strings will be unquoted.
   Reads until stop_token is found. */
void message_tokenize_get_string(struct message_tokenizer *tok,
				 string_t *str, string_t *comments,
				 const enum message_token *stop_tokens);

#endif
