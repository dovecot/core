#ifndef FTS_TOKENIZER_H
#define FTS_TOKENIZER_H

/*
 Settings are given in the form of a const char * const *settings =
 {"key, "value", "key2", "value2", NULL} array of string pairs. Some
 keys, like "no_parent" and "search" are a sort of boolean and the
 value does not matter, just mentioning the key enables the functionality.
 The array has to be NULL terminated.
*/
/* Email address header tokenizer that returns "user@domain.org" input as
   "user@domain.org" token as well as passing it through to the parent
   (generic) tokenizer, which also returns "user", "domain" and "org".
   This allows searching the mails with their individual components, but also
   allows doing an explicit "user@domain" search, which returns only mails
   matching that exact address (instead of e.g. a mail with both user@domain2
   and user2@domain words). */
/* Settings:
   "no_parent", Return only our tokens, no data for parent to process.
   Defaults to disabled. Should normally not be needed.

   "search" Remove addresses from parent data stream, so they are not processed
   further. Defaults to disabled. Enable by defining the keyword (and any
   value). */
extern const struct fts_tokenizer *fts_tokenizer_email_address;

/* Generic email content tokenizer. Cuts text into tokens. */
/* Settings: 
   "maxlen" Maximum length of token, before an arbitrary cut off is made.
   Defaults to FTS_DEFAULT_TOKEN_MAX_LENGTH.

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

/*
 Tokenizing workflow, find --> create --> filter --> destroy.
 Do init before first use and deinit after all done.
 */

/* Register all built-in tokenizers. */
void fts_tokenizers_init(void);
void fts_tokenizers_deinit(void);

const struct fts_tokenizer *fts_tokenizer_find(const char *name);

/* Create a new tokenizer. The settings are described above. */
int fts_tokenizer_create(const struct fts_tokenizer *tok_class,
			 struct fts_tokenizer *parent,
			 const char *const *settings,
			 struct fts_tokenizer **tokenizer_r,
			 const char **error_r);
void fts_tokenizer_ref(struct fts_tokenizer *tok);
void fts_tokenizer_unref(struct fts_tokenizer **tok);

/* Reset FTS tokenizer state */
void fts_tokenizer_reset(struct fts_tokenizer *tok);

/*
   Returns 1 if *token_r was returned, 0 if more data is needed, -1 on error.

   This function should be called with the same data+size until it
   returns 0. After that fts_tokenizer_final() should be called until it
   returns 0 to flush out the final token(s).

   data must contain only valid complete UTF-8 sequences, but otherwise it
   may be broken into however small pieces. (Input to this function typically
   comes from message-decoder, which returns only complete UTF-8 sequences.) */

int fts_tokenizer_next(struct fts_tokenizer *tok,
		       const unsigned char *data, size_t size,
		       const char **token_r, const char **error_r);
/* Returns same as fts_tokenizer_next(). */
int fts_tokenizer_final(struct fts_tokenizer *tok, const char **token_r,
			const char **error_r);

const char *fts_tokenizer_name(const struct fts_tokenizer *tok);

#endif
