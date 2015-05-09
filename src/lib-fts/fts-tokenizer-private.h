#ifndef FTS_TOKENIZER_PRIVATE_H
#define FTS_TOKENIZER_PRIVATE_H

#include "fts-tokenizer.h"

#define FTS_TOKENIZER_CLASSES_NR 2

struct fts_tokenizer_vfuncs {
	int (*create)(const char *const *settings,
		      struct fts_tokenizer **tokenizer_r, const char **error_r);
	void (*destroy)(struct fts_tokenizer *tok);

	void (*reset)(struct fts_tokenizer *tok);
	int (*next)(struct fts_tokenizer *tok, const unsigned char *data,
		    size_t size, size_t *skip_r, const char **token_r,
		    const char **error_r);
};

enum fts_tokenizer_parent_state {
	FTS_TOKENIZER_PARENT_STATE_ADD_DATA = 0,
	FTS_TOKENIZER_PARENT_STATE_NEXT_OUTPUT,
	FTS_TOKENIZER_PARENT_STATE_FINALIZE
};

struct fts_tokenizer {
	const char *name;
	const struct fts_tokenizer_vfuncs *v;
	int refcount;

	struct fts_tokenizer *parent;
	buffer_t *parent_input;
	enum fts_tokenizer_parent_state parent_state;

	const unsigned char *prev_data;
	size_t prev_size;
	size_t prev_skip;
	bool prev_reply_finished;
	bool skip_parents; /* Return token as is, do not hand to parents. */
};

void fts_tokenizer_register(const struct fts_tokenizer *tok_class);
void fts_tokenizer_unregister(const struct fts_tokenizer *tok_class);

#endif
