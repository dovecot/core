#ifndef LANG_TOKENIZER_H
#define LANG_TOKENIZER_H

struct lang_settings;

/*
 Settings are given in the form of a const char * const *settings =
 {"key, "value", "key2", "value2", NULL} array of string pairs. Some
 keys are a sort of boolean and the value does not matter, just mentioning
 the key enables the functionality. The array has to be NULL terminated.
*/
/* Email address header tokenizer that returns "user@domain.org" input as
   "user@domain.org" token as well as passing it through to the parent
   (generic) tokenizer, which also returns "user", "domain" and "org".
   This allows searching the mails with their individual components, but also
   allows doing an explicit "user@domain" search, which returns only mails
   matching that exact address (instead of e.g. a mail with both user@domain2
   and user2@domain words). */
extern const struct lang_tokenizer *lang_tokenizer_email_address;

/* Generic email content tokenizer. Cuts text into tokens. */
/* Settings:
   "maxlen" Maximum length of token, before an arbitrary cut off is made.
   Defaults to LANG_DEFAULT_TOKEN_MAX_LENGTH.

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
extern const struct lang_tokenizer *lang_tokenizer_generic;

enum lang_tokenizer_flags {
	/* Remove addresses from parent data stream, so they are not
	   processed further. */
	LANG_TOKENIZER_FLAG_SEARCH = 0x01,
};

/*
 Tokenizing workflow, find --> create --> filter --> destroy.
 Do init before first use and deinit after all done.
 */

/* Register all built-in tokenizers. */
void lang_tokenizers_init(void);
void lang_tokenizers_deinit(void);

const struct lang_tokenizer *lang_tokenizer_find(const char *name);

/* Create a new tokenizer. The settings are described above. */
int lang_tokenizer_create(const struct lang_tokenizer *tok_class,
			  struct lang_tokenizer *parent,
			  const struct lang_settings *set,
           		  struct event *event,
			  enum lang_tokenizer_flags flags,
			  struct lang_tokenizer **tokenizer_r,
			  const char **error_r);
void lang_tokenizer_ref(struct lang_tokenizer *tok);
void lang_tokenizer_unref(struct lang_tokenizer **tok);

/* Reset lang tokenizer state */
void lang_tokenizer_reset(struct lang_tokenizer *tok);

/*
   Returns 1 if *token_r was returned, 0 if more data is needed, -1 on error.

   This function should be called with the same data+size until it
   returns 0. After that lang_tokenizer_final() should be called until it
   returns 0 to flush out the final token(s).

   data must contain only valid complete UTF-8 sequences, but otherwise it
   may be broken into however small pieces. (Input to this function typically
   comes from message-decoder, which returns only complete UTF-8 sequences.) */

int lang_tokenizer_next(struct lang_tokenizer *tok,
			const unsigned char *data, size_t size,
			const char **token_r, const char **error_r);
/* Returns same as lang_tokenizer_next(). */
int lang_tokenizer_final(struct lang_tokenizer *tok, const char **token_r,
			 const char **error_r);

const char *lang_tokenizer_name(const struct lang_tokenizer *tok);

#endif
