/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "strfuncs.h"
#include "fts-tokenizer.h"
#include "fts-tokenizer-private.h"

ARRAY(struct fts_tokenizer) fts_tokenizer_classes;

void fts_tokenizers_init(void)
{
	if (!array_is_created(&fts_tokenizer_classes)) {
		fts_tokenizer_register(fts_tokenizer_generic);
		fts_tokenizer_register(fts_tokenizer_email_address);
	}
}

void fts_tokenizers_deinit(void)
{
	if (array_is_created(&fts_tokenizer_classes))
		array_free(&fts_tokenizer_classes);
}

/* private */
void fts_tokenizer_register(const struct fts_tokenizer *tok_class)
{
	if (!array_is_created(&fts_tokenizer_classes))
		i_array_init(&fts_tokenizer_classes, FTS_TOKENIZER_CLASSES_NR);
	array_append(&fts_tokenizer_classes, tok_class, 1);
}

/* private */
void fts_tokenizer_unregister(const struct fts_tokenizer *tok_class)
{
	const struct fts_tokenizer *tp;
	unsigned int idx;

	array_foreach(&fts_tokenizer_classes, tp) {
		if (strcmp(tp->name, tok_class->name) == 0) {
			idx = array_foreach_idx(&fts_tokenizer_classes, tp);
			array_delete(&fts_tokenizer_classes, idx, 1);
			if (array_count(&fts_tokenizer_classes) == 0)
				array_free(&fts_tokenizer_classes);
			return;
		}
	}
	i_unreached();
}

const struct fts_tokenizer *fts_tokenizer_find(const char *name)
{
	const struct fts_tokenizer *tp;

	array_foreach(&fts_tokenizer_classes, tp) {
		if (strcmp(tp->name, name) == 0)
			return tp;
	}
	return NULL;
}

const char *fts_tokenizer_name(const struct fts_tokenizer *tok)
{
	return tok->name;
}

int fts_tokenizer_create(const struct fts_tokenizer *tok_class,
			 struct fts_tokenizer *parent,
			 const char *const *settings,
			 struct fts_tokenizer **tokenizer_r,
			 const char **error_r)
{
	struct fts_tokenizer *tok;
	const char *empty_settings = NULL;

	i_assert(settings == NULL || str_array_length(settings) % 2 == 0);

	if (settings == NULL)
		settings = &empty_settings;

	if (tok_class->v->create(settings, &tok, error_r) < 0) {
		*tokenizer_r = 0;
		return -1;
	}
	tok->refcount = 1;
	tok->prev_reply_finished = TRUE;
	if (parent != NULL) {
		fts_tokenizer_ref(parent);
		tok->parent = parent;
		tok->parent_input = buffer_create_dynamic(default_pool, 128);
	}

	*tokenizer_r = tok;
	return 0;
}

void fts_tokenizer_ref(struct fts_tokenizer *tok)
{
	i_assert(tok->refcount > 0);

	tok->refcount++;
}

void fts_tokenizer_unref(struct fts_tokenizer **_tok)
{
	struct fts_tokenizer *tok = *_tok;

	i_assert(tok->refcount > 0);
	*_tok = NULL;

	if (--tok->refcount > 0)
		return;

	if (tok->parent_input != NULL)
		buffer_free(&tok->parent_input);
	if (tok->parent != NULL)
		fts_tokenizer_unref(&tok->parent);
	tok->v->destroy(tok);
}

static const char *
fts_tokenizer_next_self(struct fts_tokenizer *tok,
			const unsigned char *data, size_t size)
{
	const char *token;
	size_t skip = 0;

	i_assert(tok->prev_reply_finished ||
		 (data == tok->prev_data && size == tok->prev_size));

	if (tok->prev_reply_finished) {
		/* whole new data */
		token = tok->v->next(tok, data, size, &skip);
	} else {
		/* continuing previous data */
		i_assert(tok->prev_skip <= size);
		token = tok->v->next(tok, data + tok->prev_skip,
				     size - tok->prev_skip, &skip);
	}

	if (token != NULL) {
		i_assert(skip <= size - tok->prev_skip);
		tok->prev_data = data;
		tok->prev_size = size;
		tok->prev_skip = tok->prev_skip + skip;
		tok->prev_reply_finished = FALSE;
	} else {
		/* we need a new data block */
		tok->prev_data = NULL;
		tok->prev_size = 0;
		tok->prev_skip = 0;
		tok->prev_reply_finished = TRUE;
	}
	return token;
}

const char *
fts_tokenizer_next(struct fts_tokenizer *tok,
		   const unsigned char *data, size_t size)
{
	const char *token;

	switch (tok->parent_state) {
	case FTS_TOKENIZER_PARENT_STATE_ADD_DATA:
		token = fts_tokenizer_next_self(tok, data, size);
		if (token == NULL || tok->parent == NULL || tok->skip_parents)
			return token;
		buffer_set_used_size(tok->parent_input, 0);
		buffer_append(tok->parent_input, token, strlen(token));
		tok->parent_state++;
		/* fall through */
	case FTS_TOKENIZER_PARENT_STATE_NEXT_OUTPUT:
		token = fts_tokenizer_next(tok->parent, tok->parent_input->data,
					   tok->parent_input->used);
		if (token != NULL)
			return token;
		tok->parent_state++;
		/* fall through */
	case FTS_TOKENIZER_PARENT_STATE_FINALIZE:
		token = fts_tokenizer_next(tok->parent, NULL, 0);
		if (token != NULL)
			return token;
		/* we're finished sending this token to parent tokenizer.
		   see if our own tokenizer has more tokens available */
		tok->parent_state = FTS_TOKENIZER_PARENT_STATE_ADD_DATA;
		return fts_tokenizer_next(tok, data, size);
	default:
		i_unreached();
	}
}
