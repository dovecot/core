#ifndef LANG_TOKENIZER_PRIVATE_H
#define LANG_TOKENIZER_PRIVATE_H

#include "lang-tokenizer.h"

#define LANG_TOKENIZER_CLASSES_NR 2

struct lang_tokenizer_vfuncs {
	int (*create)(const struct lang_settings *set,
		      struct event *event,
		      enum lang_tokenizer_flags flags,
		      struct lang_tokenizer **tokenizer_r,
		      const char **error_r);
	void (*destroy)(struct lang_tokenizer *tok);

	void (*reset)(struct lang_tokenizer *tok);
	int (*next)(struct lang_tokenizer *tok, const unsigned char *data,
		    size_t size, size_t *skip_r, const char **token_r,
		    const char **error_r);
};

enum lang_tokenizer_parent_state {
	LANG_TOKENIZER_PARENT_STATE_ADD_DATA = 0,
	LANG_TOKENIZER_PARENT_STATE_NEXT_OUTPUT,
	LANG_TOKENIZER_PARENT_STATE_FINALIZE
};

struct lang_tokenizer {
	const char *name;
	const struct lang_tokenizer_vfuncs *v;
	int refcount;

	struct lang_tokenizer *parent;
	buffer_t *parent_input;
	enum lang_tokenizer_parent_state parent_state;

	const unsigned char *prev_data;
	size_t prev_size;
	size_t prev_skip;
	bool prev_reply_finished;
	bool skip_parents; /* Return token as is, do not hand to parents. */
	/* Instead of handing child tokens separately to parent tokenizer,
	   treat the returned tokens as a continuous stream. The final token
	   isn't returned until the child tokenizer also sees 0-sized data. */
	bool stream_to_parents;
	/* Parent stream still needs to be finalized, so any final pending
	   tokens will be returned. This is used only with
	   stream_to_parents=TRUE. */
	bool finalize_parent_pending;
};

void lang_tokenizer_register(const struct lang_tokenizer *tok_class);
void lang_tokenizer_unregister(const struct lang_tokenizer *tok_class);

#endif
