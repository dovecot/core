/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "fts-api-private.h"
#include "fts-tokenizer.h"
#include "fts-filter.h"
#include "fts-user.h"
#include "fts-search-args.h"

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
	const char *const *tokenp;

	/* create the OR arg first as the parent */
	or_arg = p_new(pool, struct mail_search_arg, 1);
	or_arg->type = SEARCH_OR;
	or_arg->next = orig_arg->next;

	/* now create all the child args for the OR */
	argp = &or_arg->value.subargs;
	array_foreach(tokens, tokenp) {
		arg = p_new(pool, struct mail_search_arg, 1);
		*arg = *orig_arg;
		arg->match_not = FALSE; /* we copied this to the parent SUB */
		arg->next = NULL;
		arg->value.str = p_strdup(pool, *tokenp);

		*argp = arg;
		argp = &arg->next;
	}
	return or_arg;
}

static int
fts_backend_dovecot_expand_lang_tokens(const ARRAY_TYPE(fts_user_language) *languages,
				       pool_t pool,
				       struct mail_search_arg *parent_arg,
				       const struct mail_search_arg *orig_arg,
				       const char *orig_token, const char *token)
{
	struct mail_search_arg *arg;
	struct fts_user_language *const *langp;
	ARRAY_TYPE(const_string) tokens;
	const char *token2, *error;
	int ret;

	t_array_init(&tokens, 4);
	/* first add the word exactly as it without any tokenization */
	array_append(&tokens, &orig_token, 1);
	/* then add it tokenized, but without filtering */
	array_append(&tokens, &token, 1);

	/* add the word filtered */
	array_foreach(languages, langp) {
		token2 = t_strdup(token);
		ret = (*langp)->filter == NULL ? 1 :
			fts_filter_filter((*langp)->filter, &token2, &error);
		if (ret > 0) {
			token2 = t_strdup(token2);
			array_append(&tokens, &token2, 1);
		} else if (ret < 0) {
			i_error("fts: Couldn't filter search tokens: %s", error);
			return -1;
		}
	}
	array_sort(&tokens, i_strcmp_p);
	strings_deduplicate(&tokens);

	arg = fts_search_arg_create_or(orig_arg, pool, &tokens);
	arg->next = parent_arg->value.subargs;
	parent_arg->value.subargs = arg;
	return 0;
}

static int fts_search_arg_expand(struct fts_backend *backend, pool_t pool,
				 struct mail_search_arg **argp)
{
	const ARRAY_TYPE(fts_user_language) *languages;
	struct mail_search_arg *and_arg, *orig_arg = *argp;
	const char *error, *token, *orig_token = orig_arg->value.str;
	unsigned int orig_token_len = strlen(orig_token);
	struct fts_tokenizer *tokenizer;
	int ret;

	languages = fts_user_get_all_languages(backend->ns->user);
	tokenizer = fts_user_get_search_tokenizer(backend->ns->user);

	/* we want all the tokens found from the string to be found, so create
	   a parent AND and place all the filtered token alternatives under
	   it */
	and_arg = p_new(pool, struct mail_search_arg, 1);
	and_arg->type = SEARCH_SUB;
	and_arg->match_not = orig_arg->match_not;
	and_arg->next = orig_arg->next;

	/* reset tokenizer between search args in case there's any state left
	   from some previous failure */
	fts_tokenizer_reset(tokenizer);
	while ((ret = fts_tokenizer_next(tokenizer,
					 (const void *)orig_token,
					 orig_token_len, &token, &error)) > 0) {
		if (fts_backend_dovecot_expand_lang_tokens(languages, pool, and_arg,
							   orig_arg, orig_token,
							   token) < 0)
			return -1;
	}
	while (ret >= 0 &&
	       (ret = fts_tokenizer_final(tokenizer, &token, &error)) > 0) {
		if (fts_backend_dovecot_expand_lang_tokens(languages, pool, and_arg,
							   orig_arg, orig_token,
							   token) < 0)
			return -1;
	}
	if (ret < 0) {
		i_error("fts: Couldn't tokenize search args: %s", error);
		return -1;
	}

	if (and_arg->value.subargs == NULL) {
		/* we couldn't parse any tokens from the input */
		and_arg->type = SEARCH_ALL;
		and_arg->match_not = !and_arg->match_not;
	}
	*argp = and_arg;
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
	struct mail_search_arg *args_dup;

	/* duplicate the args, so if expansion fails we haven't changed
	   anything */
	args_dup = mail_search_arg_dup(args->pool, args->args);
	if (fts_search_args_expand_tree(backend, args->pool, &args_dup) < 0)
		return -1;

	/* we'll need to re-simplify the args if we changed anything */
	args->simplified = FALSE;
	args->args = args_dup;
	mail_search_args_simplify(args);
	return 0;
}
