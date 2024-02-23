/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "strfuncs.h"
#include "lang-tokenizer.h"
#include "lang-tokenizer-private.h"

static ARRAY(const struct lang_tokenizer *) lang_tokenizer_classes;

void lang_tokenizers_init(void)
{
	if (!array_is_created(&lang_tokenizer_classes)) {
		lang_tokenizer_register(lang_tokenizer_generic);
		lang_tokenizer_register(lang_tokenizer_email_address);
	}
}

void lang_tokenizers_deinit(void)
{
	if (array_is_created(&lang_tokenizer_classes))
		array_free(&lang_tokenizer_classes);
}

/* private */
void lang_tokenizer_register(const struct lang_tokenizer *tok_class)
{
	if (!array_is_created(&lang_tokenizer_classes))
		i_array_init(&lang_tokenizer_classes, LANG_TOKENIZER_CLASSES_NR);
	array_push_back(&lang_tokenizer_classes, &tok_class);
}

/* private */
void lang_tokenizer_unregister(const struct lang_tokenizer *tok_class)
{
	const struct lang_tokenizer *const *tp;
	unsigned int idx;

	array_foreach(&lang_tokenizer_classes, tp) {
		if (strcmp((*tp)->name, tok_class->name) == 0) {
			idx = array_foreach_idx(&lang_tokenizer_classes, tp);
			array_delete(&lang_tokenizer_classes, idx, 1);
			if (array_count(&lang_tokenizer_classes) == 0)
				array_free(&lang_tokenizer_classes);
			return;
		}
	}
	i_unreached();
}

const struct lang_tokenizer *lang_tokenizer_find(const char *name)
{
	const struct lang_tokenizer *tok;

	array_foreach_elem(&lang_tokenizer_classes, tok) {
		if (strcmp(tok->name, name) == 0)
			return tok;
	}
	return NULL;
}

const char *lang_tokenizer_name(const struct lang_tokenizer *tok)
{
	return tok->name;
}

static void lang_tokenizer_self_reset(struct lang_tokenizer *tok)
{
	tok->prev_data = NULL;
	tok->prev_size = 0;
	tok->prev_skip = 0;
	tok->prev_reply_finished = TRUE;
}

int lang_tokenizer_create(const struct lang_tokenizer *tok_class,
			  struct lang_tokenizer *parent,
			  const struct lang_settings *set,
			  struct event *event,
			  enum lang_tokenizer_flags flags,
			  struct lang_tokenizer **tokenizer_r,
			  const char **error_r)
{
	struct lang_tokenizer *tok;
	if (tok_class->v->create(set, event, flags, &tok, error_r) < 0) {
		*tokenizer_r = NULL;
		return -1;
	}
	tok->refcount = 1;
	lang_tokenizer_self_reset(tok);
	if (parent != NULL) {
		lang_tokenizer_ref(parent);
		tok->parent = parent;
		tok->parent_input = buffer_create_dynamic(default_pool, 128);
	}

	*tokenizer_r = tok;
	return 0;
}

void lang_tokenizer_ref(struct lang_tokenizer *tok)
{
	i_assert(tok->refcount > 0);

	tok->refcount++;
}

void lang_tokenizer_unref(struct lang_tokenizer **_tok)
{
	struct lang_tokenizer *tok = *_tok;

	i_assert(tok->refcount > 0);
	*_tok = NULL;

	if (--tok->refcount > 0)
		return;

	buffer_free(&tok->parent_input);
	if (tok->parent != NULL)
		lang_tokenizer_unref(&tok->parent);
	tok->v->destroy(tok);
}

static int
lang_tokenizer_next_self(struct lang_tokenizer *tok,
                         const unsigned char *data, size_t size,
                         const char **token_r, const char **error_r)
{
	int ret = 0;
	size_t skip = 0;

	i_assert(tok->prev_reply_finished ||
		 (data == tok->prev_data && size == tok->prev_size));

	if (tok->prev_reply_finished) {
		/* whole new data: get the first token */
		ret = tok->v->next(tok, data, size, &skip, token_r, error_r);
	} else {
		/* continuing previous data: skip over the tokens that were
		   already returned from it and get the next token. */
		i_assert(tok->prev_skip <= size);

		const unsigned char *data_next;
		if (data != NULL)
			data_next = data + tok->prev_skip;
		else {
			i_assert(tok->prev_skip == 0 && size == 0);
			data_next = NULL;
		}
		ret = tok->v->next(tok, data_next,
				   size - tok->prev_skip, &skip,
				   token_r, error_r);
	}

	if (ret > 0) {
		/* A token was successfully returned. There could be more
		   tokens left within the provided data, so remember what part
		   of the data we used so far. */
		i_assert(skip <= size - tok->prev_skip);
		tok->prev_data = data;
		tok->prev_size = size;
		tok->prev_skip = tok->prev_skip + skip;
		tok->prev_reply_finished = FALSE;
	} else if (ret == 0) {
		/* Need more data to get the next token. The next call will
		   provide a whole new data block, so reset the prev_* state. */
		lang_tokenizer_self_reset(tok);
	}
	return ret;
}

void lang_tokenizer_reset(struct lang_tokenizer *tok)
{
	tok->v->reset(tok);
	lang_tokenizer_self_reset(tok);
}

int lang_tokenizer_next(struct lang_tokenizer *tok,
		        const unsigned char *data, size_t size,
		        const char **token_r, const char **error_r)
{
	int ret;

	switch (tok->parent_state) {
	case LANG_TOKENIZER_PARENT_STATE_ADD_DATA:
		/* Try to get the next token using this tokenizer */
		ret = lang_tokenizer_next_self(tok, data, size, token_r, error_r);
		if (ret <= 0) {
			/* error / more data needed */
			if (ret == 0 && size == 0 &&
			    tok->finalize_parent_pending) {
				/* Tokenizer input is being finalized. The
				   child tokenizer is done now, but the parent
				   tokenizer still needs to be finalized. */
				tok->finalize_parent_pending = FALSE;
				tok->parent_state =
					LANG_TOKENIZER_PARENT_STATE_FINALIZE;
				return lang_tokenizer_next(tok, NULL, 0, token_r, error_r);
			}
			break;
		}

		/* Feed the returned token to the parent tokenizer, if it
		   exists. The parent tokenizer may further split it into
		   smaller pieces. */
		if (tok->parent == NULL)
			break;
		if (tok->skip_parents) {
			/* Parent tokenizer exists, but it's skipped for now.
			   This can be used by child tokenizers to return a
			   token directly, bypassing the parent tokenizer. */
			break;
		}
		buffer_set_used_size(tok->parent_input, 0);
		buffer_append(tok->parent_input, *token_r, strlen(*token_r));
		tok->parent_state++;
		/* fall through */
	case LANG_TOKENIZER_PARENT_STATE_NEXT_OUTPUT:
		/* Return the next token from parent tokenizer */
		ret = lang_tokenizer_next(tok->parent, tok->parent_input->data,
		                         tok->parent_input->used, token_r, error_r);
		if (ret != 0)
			break;
		tok->parent_state++;
		/* fall through */
	case LANG_TOKENIZER_PARENT_STATE_FINALIZE:
		/* No more input is coming from the child tokenizer. Return the
		   final token(s) from the parent tokenizer. */
		if (!tok->stream_to_parents || size == 0) {
			ret = lang_tokenizer_next(tok->parent, NULL, 0,
						 token_r, error_r);
			if (ret != 0)
				break;
		} else {
			tok->finalize_parent_pending = TRUE;
		}
		/* We're finished handling the previous child token. See if
		   there are more child tokens available with this same data
		   input. */
		tok->parent_state = LANG_TOKENIZER_PARENT_STATE_ADD_DATA;
		return lang_tokenizer_next(tok, data, size, token_r, error_r);
	default:
		i_unreached();
	}
	/* we must not be returning empty tokens */
	i_assert(ret <= 0 || (*token_r)[0] != '\0');
	return ret;
}

int lang_tokenizer_final(struct lang_tokenizer *tok, const char **token_r,
			 const char **error_r)
{
	return lang_tokenizer_next(tok, NULL, 0, token_r, error_r);
}
