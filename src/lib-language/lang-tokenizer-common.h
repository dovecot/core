#ifndef LANG_TOKENIZER_COMMON_H
#define LANG_TOKENIZER_COMMON_H
void
lang_tokenizer_delete_trailing_partial_char(const unsigned char *data,
                                           size_t *len);
void
lang_tokenizer_delete_trailing_invalid_char(const unsigned char *data,
		   size_t *len);
#endif
