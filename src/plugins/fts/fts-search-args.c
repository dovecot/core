/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "fts-api-private.h"
#include "fts-tokenizer.h"
#include "fts-filter-private.h"
#include "fts-user.h"
#include "fts-search-args.h"
#include "fts-language.h"

#define STOPWORDS_WORKAROUND_KEY "fts_stopwords_workaround"

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
fts_backend_dovecot_expand_tokens(struct fts_filter *filter,
				  pool_t pool,
				  struct mail_search_arg *parent_arg,
				  const struct mail_search_arg *orig_arg,
				  const char *orig_token, const char *token,
				  const char **error_r)
{
	struct mail_search_arg *arg;
	ARRAY_TYPE(const_string) tokens;
	const char *token2, *error;
	int ret;

	t_array_init(&tokens, 4);
	/* first add the word exactly as it without any tokenization */
	array_push_back(&tokens, &orig_token);
	/* then add it tokenized, but without filtering */
	array_push_back(&tokens, &token);

	/* add the word filtered */
	if (filter != NULL) {
		token2 = t_strdup(token);
		ret = fts_filter_filter(filter, &token2, &error);
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
	arg->next = parent_arg->value.subargs;
	parent_arg->value.subargs = arg;
	return 0;
}

#define BOTTOM_LANGUAGE_EXPANSION TRUE
#define TOP_LANGUAGE_EXPANSION FALSE

static int
fts_backend_dovecot_tokenize_lang(struct fts_user_language *user_lang,
				  pool_t pool, struct mail_search_arg *or_arg,
				  struct mail_search_arg *orig_arg,
				  const char *orig_token,
				  bool bottom_language_expansion,
				  const char **error_r)
{
	size_t orig_token_len = strlen(orig_token);
	struct mail_search_arg *and_arg, *orig_or_args = or_arg->value.subargs;
	const char *token, *error;
	int ret;

	/* we want all the tokens found from the string to be found, so create
	   a parent AND and place all the filtered token alternatives under
	   it */
	and_arg = p_new(pool, struct mail_search_arg, 1);
	and_arg->type = SEARCH_SUB;
	and_arg->next = orig_or_args;
	or_arg->value.subargs = and_arg;

	/* reset tokenizer between search args in case there's any state left
	   from some previous failure */
	fts_tokenizer_reset(user_lang->search_tokenizer);
	while ((ret = fts_tokenizer_next(user_lang->search_tokenizer,
					 (const void *)orig_token,
					 orig_token_len, &token, &error)) > 0) {
		if (fts_backend_dovecot_expand_tokens(user_lang->filter, pool,
						      and_arg, orig_arg, orig_token,
						      token, error_r) < 0)
			return -1;
	}
	while (ret >= 0 &&
	       (ret = fts_tokenizer_final(user_lang->search_tokenizer, &token, &error)) > 0) {
		if (fts_backend_dovecot_expand_tokens(user_lang->filter, pool,
						      and_arg, orig_arg, orig_token,
						      token, error_r) < 0)
			return -1;
	}
	if (ret < 0) {
		*error_r = t_strdup_printf("Couldn't tokenize search args: %s", error);
		return -1;
	}
	if (and_arg->value.subargs == NULL) {
		if (bottom_language_expansion) {
			/* remove this empty term entirely */
			or_arg->value.subargs = orig_or_args;
		} else {
			/* The simplifier will propagate the NIL to the
			   upper operators, if required, and remove it at
			   the appropriate level */
			and_arg->type = SEARCH_NIL;
		}
	}
	return 0;
}

static int fts_search_arg_expand(struct fts_backend *backend, pool_t pool,
				 struct fts_user_language *lang,
				 bool bottom_language_expansion,
				 struct mail_search_arg **argp)
{
	const ARRAY_TYPE(fts_user_language) *languages;
	ARRAY_TYPE(fts_user_language) langs;
	struct mail_search_arg *or_arg, *orig_arg = *argp;
	const char *error, *orig_token = orig_arg->value.str;

	/* If we are invoked with no lang (null), we are operating in a bottom
	   language expansion, which is iterated here. In this case we also expect
	   to be removing NILs terms.

	   Otherwise, if we are invoked with a specific lang, we are working in
	   a top level language expansion (done above us), and we do NOT want to
	   remove the NIL terms. */
	i_assert(bottom_language_expansion == (lang == NULL));

	if (((*argp)->type == SEARCH_HEADER ||
	     (*argp)->type == SEARCH_HEADER_ADDRESS ||
	     (*argp)->type == SEARCH_HEADER_COMPRESS_LWSP) &&
	    !fts_header_has_language((*argp)->hdr_field_name)) {
		/* use only the data-language */
		lang = fts_user_get_data_lang(backend->ns->user);
	}
	if (lang != NULL) {
		/* getting here either in case of bottom language expansion OR
		   in case of language-less headers ... */
		t_array_init(&langs, 1);
		array_push_back(&langs, &lang);
		languages = &langs;
	} else {
		/* ... otherwise getting here in case of top language expansion */
		languages = fts_user_get_all_languages(backend->ns->user);
	}

	/* OR together all the different expansions for different languages.
	   it's enough for one of them to match. */
	or_arg = p_new(pool, struct mail_search_arg, 1);
	or_arg->type = SEARCH_OR;
	or_arg->match_not = orig_arg->match_not;
	or_arg->next = orig_arg->next;

	/* this reduces to one single iteration on top language expansion or
	   languageless headers */
	array_foreach_elem(languages, lang) {
		if (fts_backend_dovecot_tokenize_lang(lang, pool, or_arg,
						      orig_arg, orig_token,
						      bottom_language_expansion,
						      &error) < 0) {
			i_error("fts: %s", error);
			return -1;
		}
	}

	if (or_arg->value.subargs == NULL) {
		/* We couldn't parse any tokens from the input.
		   This can happen only in bottom level expansion,
		   as in top level we grant that expansion always
		   produces at least a NIL term */
		or_arg->type = SEARCH_ALL;
		or_arg->match_not = !or_arg->match_not;
	}
	*argp = or_arg;
	return 0;
}

static int
fts_search_args_expand_tree(struct fts_backend *backend, pool_t pool,
			    struct fts_user_language *lang,
			    bool bottom_language_expansion,
			    struct mail_search_arg **argp)
{
	int ret;

	for (; *argp != NULL; argp = &(*argp)->next) {
		switch ((*argp)->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (fts_search_args_expand_tree(backend, pool, lang,
							bottom_language_expansion,
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
				ret = fts_search_arg_expand(backend, pool, lang,
							    bottom_language_expansion,
							    argp);
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

/* Takes in input the whole expression tree, as an implicit AND of argp-list terms.
   Replaces the input expression tree with a single OR term, containing one AND
   entry for each language, each AND entry containing a copy of the original
   argp-list of terms, Then it expands each AND subargs-list according to the language.

   Input: implicit-AND(argp-list)
   Output: OR(lang1(AND(argp-list-copy), lang2(AND(argp-list-copy)) ...) */
static int
fts_search_args_expand_languages(struct fts_backend *backend, pool_t pool,
			         struct mail_search_arg **argp)
{
	if (*argp == NULL)
		return 0;

	/* ensure there is an explicit top node wich has onyl a single term,
	   be it either an AND or an OR node */
	bool top_is_or = (*argp)->type == SEARCH_OR && (*argp)->next == NULL;
	struct mail_search_arg *top_arg;
	if (top_is_or) {
		/* we already have a single top entry of type OR, reuse it */
		top_arg = (*argp);
	} else {
		/* create a single top entry of type AND with the original args */
		top_arg = p_new(pool, struct mail_search_arg, 1);
		top_arg->value.subargs = (*argp);
	}

	/* the top node will be populated from scratch with the language expansions */
	struct mail_search_arg *top_subargs = top_arg->value.subargs;
	top_arg->value.subargs = NULL;

	int direct = 0, negated = 0;
	for (struct mail_search_arg *arg = top_subargs; arg != NULL; arg = arg->next, ++direct)
		if (arg->match_not) ++negated, --direct;

	#define XOR != /* '!=' is the boolean equivalent of bitwise xor '^' */

	/* likely we might want a simplification that pushes all the negations
	   toward the root of the node before doing this, rather than the current
	   one that pushes them toward the leaves ? */

	/* THIS CASE IS THE GREY ZONE ---------------------------------|______________| */
	bool want_invert = negated == 0 ? FALSE : direct == 0 ? TRUE : negated > direct;
	bool invert = want_invert XOR top_arg->match_not;

	if (invert) {
		top_arg->type = top_arg->type != SEARCH_OR ? SEARCH_OR : SEARCH_SUB;
		for (struct mail_search_arg *arg = top_subargs; arg != NULL; arg = arg->next)
			arg->match_not = !arg->match_not;
	}

	const ARRAY_TYPE(fts_user_language) *languages =
		fts_user_get_all_languages(backend->ns->user);
	struct fts_user_language *lang;
	array_foreach_elem(languages, lang) {
		struct mail_search_arg *lang_arg = p_new(pool, struct mail_search_arg, 1);
		lang_arg->type = top_is_or XOR invert ? SEARCH_OR : SEARCH_SUB;
		lang_arg->match_not = invert;
		lang_arg->value.subargs = mail_search_arg_dup(pool, top_subargs);

		if (fts_search_args_expand_tree(backend, pool, lang,
						TOP_LANGUAGE_EXPANSION,
						&lang_arg->value.subargs) < 0)
			return -1;

		lang_arg->next = top_arg->value.subargs;
		top_arg->value.subargs = lang_arg;
	}

	*argp = top_arg;
	return 0;
}


static bool fts_lang_has_stopwords(const struct fts_user_language *lang)
{
	struct fts_filter *filter;
	for (filter = lang->filter; filter != NULL; filter = filter->parent)
		if (strcmp(filter->class_name, "stopwords") == 0)
			return TRUE;
	return FALSE;
}

static bool
fts_search_args_expand_language_top_level(struct fts_backend *backend)
{
	const char *setting = mail_user_plugin_getenv(
		backend->ns->user, STOPWORDS_WORKAROUND_KEY);

	if (setting != NULL) {
		if (strcasecmp(setting, "no") == 0) return FALSE;
		if (strcasecmp(setting, "yes") == 0) return TRUE;
		/* otherwise we imply auto */
	}

	struct fts_user_language *lang;
	const ARRAY_TYPE(fts_user_language) *languages =
		fts_user_get_all_languages(backend->ns->user);

	unsigned int langs_count = 0;
	bool stopwords = FALSE;
	array_foreach_elem(languages, lang) {
		if (strcmp(lang->lang->name, "data") == 0)
			continue;

		if (fts_lang_has_stopwords(lang))
			stopwords = TRUE;

		if (stopwords && ++langs_count > 1)
			return TRUE;
	}
	return FALSE;
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

	if (fts_search_args_expand_language_top_level(backend)) {
		if (fts_search_args_expand_languages(
			backend, args->pool, &args_dup) < 0)
			return -1;
	} else {
		if (fts_search_args_expand_tree(
			backend, args->pool, NULL, BOTTOM_LANGUAGE_EXPANSION,
			&args_dup) < 0)
			return -1;
	}

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
