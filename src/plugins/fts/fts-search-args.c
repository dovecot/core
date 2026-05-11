/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "fts-api-private.h"
#include "lang-tokenizer.h"
#include "lang-filter.h"
#include "lang-user.h"
#include "fts-user.h"
#include "fts-search-args.h"

#include <ctype.h>

static void strings_deduplicate(ARRAY_TYPE(const_string) *arr)
{
	const char *const *strings;
	unsigned int i, count;

	strings = array_get(arr, &count);
	for (i = 1; i < count; ) {
		if (strcmp(strings[i-1], strings[i]) == 0) {
			array_delete(arr, i, 1);
			strings = array_get(arr, &count);
		} else {
			i++;
		}
	}
}

static struct mail_search_arg *
fts_search_arg_create_or(const struct mail_search_arg *orig_arg, pool_t pool,
			 const ARRAY_TYPE(const_string) *tokens)
{
	struct mail_search_arg *arg, *or_arg, **argp;
	const char *token;

	/* create the OR arg first as the parent */
	or_arg = p_new(pool, struct mail_search_arg, 1);
	or_arg->type = SEARCH_OR;

	/* now create all the child args for the OR */
	argp = &or_arg->value.subargs;
	i_assert(orig_arg->type == SEARCH_TEXT ||
		 orig_arg->type == SEARCH_BODY ||
		 orig_arg->type == SEARCH_HEADER ||
		 orig_arg->type == SEARCH_HEADER_ADDRESS ||
		 orig_arg->type == SEARCH_HEADER_COMPRESS_LWSP);
	array_foreach_elem(tokens, token) {
		arg = p_new(pool, struct mail_search_arg, 1);
		*arg = *orig_arg;
		arg->match_not = FALSE; /* we copied this to the root OR */
		arg->next = NULL;
		arg->value.str = p_strdup(pool, token);

		*argp = arg;
		argp = &arg->next;
	}
	return or_arg;
}

static int
fts_backend_dovecot_expand_tokens(struct lang_filter *filter,
				  pool_t pool,
				  struct mail_search_arg *parent_arg,
				  const struct mail_search_arg *orig_arg,
				  const char *orig_token, const char *token,
				  enum mail_search_arg_flag token_flag,
				  const char **error_r)
{
	struct mail_search_arg *arg, *subarg;
	ARRAY_TYPE(const_string) tokens;
	const char *token2, *error;
	int ret;

	t_array_init(&tokens, 4);
	/* first add the word exactly as it without any tokenization */
	if (orig_token != NULL)
		array_push_back(&tokens, &orig_token);
	/* then add it tokenized, but without filtering */
	array_push_back(&tokens, &token);

	/* add the word filtered */
	if (filter != NULL) {
		token2 = t_strdup(token);
		ret = lang_filter(filter, &token2, &error);
		if (ret > 0) {
			token2 = t_strdup(token2);
			array_push_back(&tokens, &token2);
		} else if (ret < 0) {
			*error_r = t_strdup_printf("Couldn't filter search token: %s", error);
			return -1;
		} else {
			/* The filter dropped the token, which means it was
			   never even indexed. Ignore this word entirely in the
			   search query. */
			return 0;
		}
	}
	array_sort(&tokens, i_strcmp_p);
	strings_deduplicate(&tokens);

	arg = fts_search_arg_create_or(orig_arg, pool, &tokens);
	if (token_flag != 0) {
		for (subarg = arg->value.subargs; subarg != NULL; subarg = subarg->next) {
			if (orig_token != NULL && strcmp(subarg->value.str, orig_token) == 0)
				subarg->value.search_flags |= MAIL_SEARCH_ARG_FLAG_PHRASE_FULL;
			else
				subarg->value.search_flags |= token_flag;
		}
	}
	arg->next = parent_arg->value.subargs;
	parent_arg->value.subargs = arg;
	return 0;
}

static int
fts_backend_dovecot_tokenize_lang(struct fts_backend *backend,
				  struct language_user *user_lang,
				  pool_t pool, struct mail_search_arg *or_arg,
				  struct mail_search_arg *orig_arg,
				  const char *orig_token, const char **error_r)
{
	/* Phrase search strategy:
	 *
	 * When FTS_BACKEND_FLAG_SEARCH_ARGS_V2 is set:
	 *   1. The original phrase string is added as a separate SEARCH_TEXT arg
	 *      with PHRASE_FULL flag.
	 *   2. Each tokenized word is added as a SEARCH_TEXT arg with PHRASE_TERM
	 *      flag (PHRASE_FIRST_TERM for the first word).
	 *   3. The phrase arg and tokenized args are placed under the same AND
	 *      (SUB) parent. Backends that support this flag treat the tokenized
	 *      args as a filter to reduce the search space, while the phrase arg
	 *      is handled by the core FTS fallback for exact matching.
	 *
	 * When the flag is NOT set (old behavior):
	 *   1. Each tokenized word is OR'd with the original phrase string.
	 *   2. Backends see all terms as equal alternatives. */

	size_t orig_token_len = strlen(orig_token);
	struct mail_search_arg *and_arg, *orig_or_args = or_arg->value.subargs;
	const char *token, *error;
	ARRAY_TYPE(const_string) tokenizer_tokens;
	unsigned int i, count;
	int ret;

	/* we want all the tokens found from the string to be found, so create
	   a parent AND and place all the filtered token alternatives under
	   it */
	and_arg = p_new(pool, struct mail_search_arg, 1);
	and_arg->type = SEARCH_SUB;
	and_arg->next = orig_or_args;
	or_arg->value.subargs = and_arg;

	t_array_init(&tokenizer_tokens, 16);

	/* reset tokenizer between search args in case there's any state left
	   from some previous failure */
	lang_tokenizer_reset(user_lang->search_tokenizer);
	while ((ret = lang_tokenizer_next(user_lang->search_tokenizer,
					 (const void *)orig_token,
					 orig_token_len, &token, &error)) > 0) {
		array_push_back(&tokenizer_tokens, &token);
	}
	while (ret >= 0 &&
	       (ret = lang_tokenizer_final(user_lang->search_tokenizer, &token, &error)) > 0) {
		array_push_back(&tokenizer_tokens, &token);
	}
	if (ret < 0) {
		*error_r = t_strdup_printf("Couldn't tokenize search args: %s", error);
		return -1;
	}

	const char *const *tokens = array_get(&tokenizer_tokens, &count);
	bool phrase_and = HAS_ANY_BITS(backend->flags, FTS_BACKEND_FLAG_SEARCH_ARGS_V2);
	/* We only treat this as a phrase if it actually contains spaces. If it
	   doesn't contain spaces but tokenizes to multiple tokens (e.g. dotted
	   words or email addresses), we don't want to treat it as a phrase
	   because backends may handle these differently than actual phrases.
	   Specifically, if we mark a single string as a phrase, backends
	   might only match the split tokens and skip the original string.
	   Since the core FTS fallback search logic requires a literal match for
	   phrases, this could break matching for single strings that happen to
	   split during tokenization. */
	bool is_phrase = false;
	if (count > 1) {
		for (const char *p = orig_token; *p != '\0'; p++) {
			if (i_isspace(*p)) {
				is_phrase = true;
				break;
			}
		}
	}

	/* Move full phrase term to the base of the AND argument. */
	if (phrase_and && is_phrase) {
		struct mail_search_arg *phrase_arg;
		phrase_arg = p_new(pool, struct mail_search_arg, 1);
		*phrase_arg = *orig_arg;
		phrase_arg->next = NULL;
		phrase_arg->match_not = FALSE;
		phrase_arg->match_always = FALSE;
		phrase_arg->nonmatch_always = FALSE;
		phrase_arg->value.str = p_strdup(pool, orig_token);
		phrase_arg->value.search_flags |= MAIL_SEARCH_ARG_FLAG_PHRASE_FULL;
		and_arg->value.subargs = phrase_arg;
	}

	for (i = 0; i < count; i++) {
		enum mail_search_arg_flag token_flag = 0;
		if (is_phrase) {
			token_flag |= MAIL_SEARCH_ARG_FLAG_PHRASE_TERM;
			if (i == 0)
				token_flag |= MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM;
		}

		if (fts_backend_dovecot_expand_tokens(user_lang->filter, pool,
						      and_arg, orig_arg,
						      (phrase_and && is_phrase) ? NULL : orig_token,
						      tokens[i], token_flag,
						      error_r) < 0)
			return -1;
	}

	if (and_arg->value.subargs == NULL) {
		/* nothing was actually expanded, remove the empty and_arg */
		or_arg->value.subargs = orig_or_args;
	}
	return 0;
}

static int fts_search_arg_expand(struct fts_backend *backend, pool_t pool,
				 struct mail_search_arg **argp)
{
	struct event *event = backend->event;
	const ARRAY_TYPE(language_user) *languages;
	struct language_user *lang;
	struct mail_search_arg *or_arg, *orig_arg = *argp;
	const char *error, *orig_token = orig_arg->value.str;

	if (((*argp)->type == SEARCH_HEADER ||
	     (*argp)->type == SEARCH_HEADER_ADDRESS ||
	     (*argp)->type == SEARCH_HEADER_COMPRESS_LWSP) &&
	    !fts_header_has_language((*argp)->hdr_field_name)) {
		/* use only the data-language */
		languages = lang_user_get_data_languages(backend->ns->user);
	} else {
		languages = lang_user_get_all_languages(backend->ns->user);
	}

	/* OR together all the different expansions for different languages.
	   it's enough for one of them to match. */
	or_arg = p_new(pool, struct mail_search_arg, 1);
	or_arg->type = SEARCH_OR;
	or_arg->match_not = orig_arg->match_not;
	or_arg->next = orig_arg->next;

	array_foreach_elem(languages, lang) {
		if (fts_backend_dovecot_tokenize_lang(backend, lang, pool, or_arg,
						      orig_arg, orig_token, &error) < 0) {
			e_error(event, "%s", error);
			return -1;
		}
	}

	if (or_arg->value.subargs == NULL) {
		/* we couldn't parse any tokens from the input */
		or_arg->type = SEARCH_ALL;
		or_arg->match_not = !or_arg->match_not;
	}
	*argp = or_arg;
	return 0;
}

static int
fts_search_args_expand_tree(struct fts_backend *backend, pool_t pool,
			    struct mail_search_arg **argp)
{
	int ret;

	for (; *argp != NULL; argp = &(*argp)->next) {
		switch ((*argp)->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (fts_search_args_expand_tree(backend, pool,
							&(*argp)->value.subargs) < 0)
				return -1;
			break;
		case SEARCH_HEADER:
		case SEARCH_HEADER_ADDRESS:
		case SEARCH_HEADER_COMPRESS_LWSP:
			if ((*argp)->value.str[0] == '\0') {
				/* we're testing for the existence of
				   the header */
				break;
			}
			/* fall through */
		case SEARCH_BODY:
		case SEARCH_TEXT:
			T_BEGIN {
				ret = fts_search_arg_expand(backend, pool, argp);
			} T_END;
			if (ret < 0)
				return -1;
			break;
		default:
			break;
		}
	}
	return 0;
}

int fts_search_args_expand(struct fts_backend *backend,
			   struct mail_search_args *args)
{
	struct mail_search_arg *args_dup, *orig_args = args->args;

	/* don't keep re-expanding every time the search args are used.
	   this is especially important to avoid an assert-crash in
	   index_search_result_update_flags(). */
	if (args->fts_expanded)
		return 0;
	args->fts_expanded = TRUE;

	/* duplicate the args, so if expansion fails we haven't changed
	   anything */
	args_dup = mail_search_arg_dup(args->pool, args->args);

	if (fts_search_args_expand_tree(backend, args->pool, &args_dup) < 0)
		return -1;

	/* we'll need to re-simplify the args if we changed anything */
	args->simplified = FALSE;
	args->args = args_dup;
	mail_search_args_simplify(args);

	/* duplicated args aren't initialized */
	i_assert(args->init_refcount > 0);
	mail_search_arg_init(args, args_dup);
	mail_search_arg_deinit(orig_args);
	return 0;
}
