#ifndef FTS_TOKENIZER_H
#define FTS_TOKENIZER_H

/*
 Settings are given in the form of a const char * const *settings =
 {"key, "value", "key2", "value2", NULL} array of string pairs.
 The array has to be NULL terminated.
*/
/* Email address header tokenizer that returns "user@domain.org" input as
   "user@domain.org" token as well as passing it through to the parent
   (generic) tokenizer, which also returns "user", "domain" and "org".
   This allows searching the mails with their individual components, but also
   allows doing an explicit "user@domain" search, which returns only mails
   matching that exact address (instead of e.g. a mail with both user@domain2
   and user2@domain words). */
/* Settings: "have_parent", Return not only our tokens, but also data
   for parent to process. Defaults to 1. Should normally not need to
   be changed. */
extern const struct fts_tokenizer *fts_tokenizer_email_address;
#define FTS_TOKENIZER_EMAIL_ADDRESS_NAME "email-address"

/* Generic email content tokenizer. Cuts text into tokens. */
/* Settings: "maxlen" Maximum length of token, before an arbitary cut
   off is made. Defaults to FTS_DEFAULT_TOKEN_MAX_LENGTH.
   "algorithm", accepted values are "simple" or "tr29". Defines the
   method for looking for word boundaries. Simple is faster and will
   work for many texts, especially those using latin alphabets, but
   leaves corner cases. The tr29 implements a version of Unicode
   technical report 29 word boundary lookup. It might work better with
   e.g. texts containing Katakana or hebrew characters, but it is not
   possible to use a single algorithm for all existing languages. It
   is also significantly slower than simple. The algorithms also
   differ in some details, e.g. simple will cut "a.b" and tr29 will
   not. The default is "simple" */
extern const struct fts_tokenizer *fts_tokenizer_generic;
#define FTS_TOKENIZER_GENERIC_NAME "generic"

const struct fts_tokenizer *fts_tokenizer_find(const char *name);

/* Create a new tokenizer. The settings is an array of key,value pairs. */
int fts_tokenizer_create(const struct fts_tokenizer *tok_class,
			 struct fts_tokenizer *parent,
			 const char *const *settings,
			 struct fts_tokenizer **tokenizer_r,
			 const char **error_r);
void fts_tokenizer_ref(struct fts_tokenizer *tok);
void fts_tokenizer_unref(struct fts_tokenizer **tok);

/* Returns the next token, or NULL if more data is needed for the next token.
   This function should be called with the same data+size until it returns
   NULL. When the input is finished, this function should be still be called
   with size=0 to flush out the final token(s).

   data must contain only valid complete UTF-8 sequences, but otherwise it
   may be broken into however small pieces. */
const char *
fts_tokenizer_next(struct fts_tokenizer *tok,
		   const unsigned char *data, size_t size);

#endif
