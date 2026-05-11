/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "test-common.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mail-search.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "fts-api-private.h"
#include "fts-search-args.h"
#include "lang-user.h"
#include "lang-tokenizer.h"
#include "lang-filter.h"

/* Mocks */
static const char *const *mock_tokens;
static int mock_token_idx;

static void test_lang_tokenizer_reset(struct lang_tokenizer *tok ATTR_UNUSED) {
	mock_token_idx = 0;
}

static int test_lang_tokenizer_next(struct lang_tokenizer *tok ATTR_UNUSED,
				     const void *data ATTR_UNUSED,
				     size_t len ATTR_UNUSED,
				     const char **token_r,
				     const char **error_r ATTR_UNUSED) {
	if (mock_tokens == NULL || mock_tokens[mock_token_idx] == NULL) return 0;
	*token_r = mock_tokens[mock_token_idx++];
	return 1;
}

static int test_lang_tokenizer_final(struct lang_tokenizer *tok ATTR_UNUSED,
				      const char **token_r ATTR_UNUSED,
				      const char **error_r ATTR_UNUSED) {
	return 0;
}

static int test_lang_filter(struct lang_filter *filter ATTR_UNUSED,
			    const char **token ATTR_UNUSED,
			    const char **error_r ATTR_UNUSED) {
	/* Return 1 (keep) */
	return 1;
}

static struct language_user test_lang_user_struct;
static ARRAY_TYPE(language_user) test_languages;

static const ARRAY_TYPE(language_user) *
test_lang_user_get_all_languages(struct mail_user *user ATTR_UNUSED) {
	return &test_languages;
}

static const ARRAY_TYPE(language_user) *
test_lang_user_get_data_languages(struct mail_user *user ATTR_UNUSED) {
	return &test_languages;
}

static bool test_fts_header_has_language(const char *name ATTR_UNUSED) {
	return FALSE;
}

/* Redirects */
#define lang_tokenizer_reset test_lang_tokenizer_reset
#define lang_tokenizer_next test_lang_tokenizer_next
#define lang_tokenizer_final test_lang_tokenizer_final
/* Use function macro to avoid renaming struct lang_filter */
#define lang_filter(f, t, e) test_lang_filter(f, t, e)
#define lang_user_get_all_languages test_lang_user_get_all_languages
#define lang_user_get_data_languages test_lang_user_get_data_languages
#define fts_header_has_language test_fts_header_has_language

#include "fts-search-args.c"

/* Tests */

static struct fts_backend *test_backend;
static struct mail_user *test_user;
static struct mail_namespace *test_ns;

static void test_setup(void)
{
	test_user = i_new(struct mail_user, 1);
	test_ns = i_new(struct mail_namespace, 1);
	test_ns->user = test_user;

	test_backend = i_new(struct fts_backend, 1);
	test_backend->ns = test_ns;
	test_backend->event = event_create(NULL);
	test_backend->flags = FTS_BACKEND_FLAG_TOKENIZED_INPUT;

	i_array_init(&test_languages, 1);
	struct language_user *item = &test_lang_user_struct;
	array_push_back(&test_languages, &item);
}

static void test_teardown(void)
{
	array_free(&test_languages);
	event_unref(&test_backend->event);
	i_free(test_backend);
	i_free(test_ns);
	i_free(test_user);
}

static void test_single_word(void)
{
	test_begin("single word");

	/* Setup mock tokens for "foo" */
	static const char *const tokens[] = { "foo", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool, &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Structure:
	   arg_exp (SEARCH_OR) -> subargs (SEARCH_SUB) -> subargs (SEARCH_OR) -> subargs ("foo")
	*/

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub->type == SEARCH_SUB);
	struct mail_search_arg *or_arg = sub->value.subargs;
	test_assert(or_arg->type == SEARCH_OR);

	struct mail_search_arg *term = or_arg->value.subargs;
	test_assert_strcmp(term->value.str, "foo");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);

	mail_search_args_simplify(args);

	/* Simplified Structure:
	   SEARCH_TEXT ("foo")
	*/
	arg = args->args;
	test_assert(arg->type == SEARCH_TEXT);
	test_assert_strcmp(arg->value.str, "foo");
	test_assert(HAS_NO_BITS(arg->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(arg->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(arg->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(arg->next == NULL);

	mail_search_args_unref(&args);
	test_end();
}

static void test_phrase_old_args_structure(void)
{
	test_begin("phrase (old args structure)");

	/* Setup mock tokens for "foo bar" */
	static const char *const tokens[] = { "foo", "bar", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo bar";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool, &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Structure:
	 * OR flags=0 str=''
	 *   SUB flags=0 str=''
	 *     OR flags=0 str=''
	 *       TEXT flags=8 str='bar'
	 *       TEXT flags=2 str='foo bar'
	 *     OR flags=0 str=''
	 *       TEXT flags=12 str='foo'
	 *       TEXT flags=2 str='foo bar'
	 */

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub->type == SEARCH_SUB);

	struct mail_search_arg *p = sub->value.subargs;

	test_assert(p->type == SEARCH_OR);
	test_assert(HAS_NO_BITS(p->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(p->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(p->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	struct mail_search_arg *or1 = p->value.subargs;

	test_assert(or1 != NULL);
	test_assert(or1->type == SEARCH_TEXT);
	test_assert_strcmp(or1->value.str, "bar");
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(or1->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	or1 = or1->next;

	test_assert(or1 != NULL);
	test_assert(or1->type == SEARCH_TEXT);
	test_assert_strcmp(or1->value.str, "foo bar");
	test_assert(HAS_ANY_BITS(or1->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	or1 = or1->next;

	test_assert(or1 == NULL);

	p = p->next;

	test_assert(p != NULL);

	struct mail_search_arg *or2 = p->value.subargs;

	test_assert(or2 != NULL);
	test_assert(or2->type == SEARCH_TEXT);
	test_assert_strcmp(or2->value.str, "foo");
	test_assert(HAS_NO_BITS(or2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(or2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(or2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	or2 = or2->next;

	test_assert(or2 != NULL);
	test_assert(or2->type == SEARCH_TEXT);
	test_assert_strcmp(or2->value.str, "foo bar");
	test_assert(HAS_ANY_BITS(or2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(or2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	or2 = or2->next;

	test_assert(or2 == NULL);

	mail_search_args_simplify(args);

	/* Simplified Structure:
	 * OR flags=0 str=''
	 *   SUB flags=0 str=''
	 *     TEXT flags=8 str='bar'
	 *     TEXT flags=12 str='foo'
	 *   TEXT flags=2 str='foo bar'
	 */
	arg = args->args;
	test_assert(arg->type == SEARCH_OR);

	/* Check children of OR */
	struct mail_search_arg *child1 = arg->value.subargs;
	test_assert(child1 != NULL);

	/* Child 1 should be SUB("foo", "bar") */
	test_assert(child1->type == SEARCH_SUB);
	struct mail_search_arg *sub_child = child1->value.subargs;

	test_assert(sub_child != NULL);
	/* SUB children order: "bar" then "foo" */
	test_assert(sub_child->type == SEARCH_TEXT);
	test_assert_strcmp(sub_child->value.str, "bar");
	test_assert(HAS_NO_BITS(sub_child->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(sub_child->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(HAS_NO_BITS(sub_child->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));

	sub_child = sub_child->next;
	test_assert(sub_child != NULL);
	test_assert(sub_child->type == SEARCH_TEXT);
	test_assert_strcmp(sub_child->value.str, "foo");
	test_assert(HAS_NO_BITS(sub_child->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(sub_child->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(sub_child->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	test_assert(sub_child->next == NULL);

	/* Child 2 should be TEXT "foo bar" */
	struct mail_search_arg *child2 = child1->next;
	test_assert(child2 != NULL);
	test_assert(child2->type == SEARCH_TEXT);
	test_assert_strcmp(child2->value.str, "foo bar");
	test_assert(HAS_ANY_BITS(child2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(child2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(HAS_NO_BITS(child2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));

	test_assert(child2->next == NULL);

	mail_search_args_unref(&args);
	test_end();
}

static void test_phrase_new_args_structure(void)
{
	test_begin("phrase (new args structure)");

	test_backend->flags |= FTS_BACKEND_FLAG_SEARCH_ARGS_V2;

	/* Setup mock tokens for "foo bar" */
	static const char *const tokens[] = { "foo", "bar", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo bar";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool, &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Structure:
	 * OR flags=0 str=''
	 *   SUB flags=0 str=''
	 *     OR flags=0 str=''
	 *       TEXT flags=8 str='bar'
	 *     OR flags=0 str=''
	 *       TEXT flags=12 str='foo'
	 *     TEXT flags=2 str='foo bar'
	 */

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub_or = arg_exp->value.subargs;

	test_assert(sub_or->type == SEARCH_SUB);
	struct mail_search_arg *sub = sub_or->value.subargs;

	test_assert(sub->type == SEARCH_OR);
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	struct mail_search_arg *or1 = sub->value.subargs;

	test_assert(or1 != NULL);
	test_assert(or1->type == SEARCH_TEXT);
	test_assert_strcmp(or1->value.str, "bar");
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(or1->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	test_assert(or1->next == NULL);

	sub = sub->next;

	test_assert(sub->type == SEARCH_OR);
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	struct mail_search_arg *or2 = sub->value.subargs;

	test_assert(or2 != NULL);
	test_assert(or2->type == SEARCH_TEXT);
	test_assert_strcmp(or2->value.str, "foo");
	test_assert(HAS_NO_BITS(or2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(or2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(or2->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	test_assert(or2->next == NULL);

	sub = sub->next;

	test_assert(sub != NULL);
	test_assert(sub->type == SEARCH_TEXT);
	test_assert_strcmp(sub->value.str, "foo bar");
	test_assert(HAS_ANY_BITS(sub->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(sub->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	test_assert(sub->next == NULL);

	mail_search_args_simplify(args);

	/* Simplified Structure:
	* TEXT flags=8 str='bar'
	* TEXT flags=12 str='foo'
	* TEXT flags=2 str='foo bar'
	*/

	arg = args->args;

	test_assert(arg != NULL);
	test_assert(arg->type == SEARCH_TEXT);
	test_assert_strcmp(arg->value.str, "bar");

	arg = arg->next;

	test_assert(arg != NULL);
	test_assert(arg->type == SEARCH_TEXT);
	test_assert_strcmp(arg->value.str, "foo");

	arg = arg->next;

	test_assert(arg != NULL);
	test_assert(arg->type == SEARCH_TEXT);
	test_assert_strcmp(arg->value.str, "foo bar");

	test_assert(arg->next == NULL);

	mail_search_args_unref(&args);
	test_end();
}

static void test_phrase_with_tab_whitespace(void)
{
	test_begin("phrase with tab whitespace");

	test_backend->flags |= FTS_BACKEND_FLAG_SEARCH_ARGS_V2;

	/* Setup mock tokens for "foo\tbar" (tab-separated, should be a phrase) */
	static const char *const tokens[] = { "foo", "bar", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo\tbar";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool,
					  &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Structure with phrase_and=true and is_phrase=true (tab detected):
	 *
	 * OR
	 *   SUB
	 *     OR
	 *       TEXT flags=8 str='bar'        (PHRASE_TERM)
	 *     OR
	 *       TEXT flags=12 str='foo'       (PHRASE_FIRST_TERM | PHRASE_TERM)
	 *     TEXT flags=2 str='foo\tbar'     (PHRASE_FULL)
	 */

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub->type == SEARCH_SUB);

	/* First OR: tokenized "bar" (PHRASE_TERM only) */
	struct mail_search_arg *or1 = sub->value.subargs;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	struct mail_search_arg *term = or1->value.subargs;
	test_assert(term != NULL && term->type == SEARCH_TEXT);
	test_assert_strcmp(term->value.str, "bar");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);  /* OR has exactly one child */

	/* Second OR: tokenized "foo" (PHRASE_FIRST_TERM | PHRASE_TERM) */
	or1 = or1->next;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	term = or1->value.subargs;
	test_assert(term != NULL && term->type == SEARCH_TEXT);
	test_assert_strcmp(term->value.str, "foo");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);  /* OR has exactly one child */

	/* Third: full phrase "foo\tbar" (PHRASE_FULL) */
	or1 = or1->next;
	test_assert(or1 != NULL && or1->type == SEARCH_TEXT);
	test_assert_strcmp(or1->value.str, "foo\tbar");
	test_assert(HAS_ANY_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(or1->next == NULL);  /* End of SUB children */

	mail_search_args_unref(&args);
	test_end();
}

static void test_three_word_phrase(void)
{
	test_begin("three word phrase (new args structure)");

	test_backend->flags |= FTS_BACKEND_FLAG_SEARCH_ARGS_V2;

	/* Setup mock tokens for "foo bar baz" (three-word phrase) */
	static const char *const tokens[] = { "foo", "bar", "baz", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo bar baz";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool,
					  &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Structure with phrase_and=true and is_phrase=true:
	 *
	 * OR
	 *   SUB
	 *     OR
	 *       TEXT flags=8 str='baz'        (PHRASE_TERM)
	 *     OR
	 *       TEXT flags=8 str='bar'        (PHRASE_TERM)
	 *     OR
	 *       TEXT flags=12 str='foo'       (PHRASE_FIRST_TERM | PHRASE_TERM)
	 *     TEXT flags=2 str='foo bar baz'  (PHRASE_FULL)
	 */

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub->type == SEARCH_SUB);

	/* First OR: last token "baz" (PHRASE_TERM only) */
	struct mail_search_arg *or1 = sub->value.subargs;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	struct mail_search_arg *term = or1->value.subargs;
	test_assert(term != NULL && term->type == SEARCH_TEXT);
	test_assert_strcmp(term->value.str, "baz");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);

	/* Second OR: middle token "bar" (PHRASE_TERM only) */
	or1 = or1->next;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	term = or1->value.subargs;
	test_assert(term != NULL && term->type == SEARCH_TEXT);
	test_assert_strcmp(term->value.str, "bar");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);

	/* Third OR: first token "foo" (PHRASE_FIRST_TERM | PHRASE_TERM) */
	or1 = or1->next;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	term = or1->value.subargs;
	test_assert(term != NULL && term->type == SEARCH_TEXT);
	test_assert_strcmp(term->value.str, "foo");
	test_assert(HAS_NO_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_ANY_BITS(term->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(term->next == NULL);

	/* Fourth: full phrase "foo bar baz" (PHRASE_FULL) */
	or1 = or1->next;
	test_assert(or1 != NULL && or1->type == SEARCH_TEXT);
	test_assert_strcmp(or1->value.str, "foo bar baz");
	test_assert(HAS_ANY_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FIRST_TERM));
	test_assert(HAS_NO_BITS(or1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));
	test_assert(or1->next == NULL);

	mail_search_args_unref(&args);
	test_end();
}

static void test_single_word_split(void)
{
	test_begin("single word split (e.g. email or dotted word)");

	test_backend->flags |= FTS_BACKEND_FLAG_SEARCH_ARGS_V2;

	/* Setup mock tokens for "foo.bar" (a single word that tokenizes into
	   multiple parts) */
	static const char *const tokens[] = { "foo", "bar", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	struct mail_search_args *args = mail_search_build_init();
	struct mail_search_arg *arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_TEXT;
	arg->value.str = "foo.bar";
	args->args = arg;

	test_assert(fts_search_arg_expand(test_backend, args->pool,
					  &args->args) == 0);

	struct mail_search_arg *arg_exp = args->args;

	/* Under the broken logic, this single word would be treated as a phrase
	   (PHRASE_FULL added, and phrase parsing applied).
	   With the fix, it should just be expanded normally without phrase
	   flags. */

	test_assert(arg_exp->type == SEARCH_OR);
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub->type == SEARCH_SUB);

	/* Check first token expansion ("bar").
	   With the bug, the phrase logic passes NULL for orig_token, so
	   "foo.bar" is missing, and "bar" has the PHRASE_TERM flag set. */
	struct mail_search_arg *or1 = sub->value.subargs;
	test_assert(or1 != NULL && or1->type == SEARCH_OR);

	struct mail_search_arg *term1 = or1->value.subargs;
	test_assert(term1 != NULL && term1->type == SEARCH_TEXT);
	test_assert_strcmp(term1->value.str, "bar");
	test_assert(HAS_NO_BITS(term1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	term1 = term1->next;
	test_assert(term1 != NULL && term1->type == SEARCH_TEXT);
	test_assert_strcmp(term1->value.str, "foo.bar");
	test_assert(HAS_NO_BITS(term1->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));

	/* Check second token expansion ("foo") */
	struct mail_search_arg *or2 = or1->next;
	test_assert(or2 != NULL && or2->type == SEARCH_OR);

	struct mail_search_arg *term2 = or2->value.subargs;
	test_assert(term2 != NULL && term2->type == SEARCH_TEXT);
	test_assert_strcmp(term2->value.str, "foo");
	test_assert(HAS_NO_BITS(term2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_TERM));

	term2 = term2->next;
	test_assert(term2 != NULL && term2->type == SEARCH_TEXT);
	test_assert_strcmp(term2->value.str, "foo.bar");
	test_assert(HAS_NO_BITS(term2->value.search_flags,
				MAIL_SEARCH_ARG_FLAG_PHRASE_FULL));

	test_assert(or2->next == NULL);

	mail_search_args_unref(&args);
	test_end();
}

/* Setup test_backend->flags with the required search args before calling. */
static void test_phrase_with_sibling_next_helper(void)
{
	/* Setup mock tokens for "foo bar" */
	static const char *const tokens[] = { "foo", "bar", NULL };
	mock_tokens = tokens;
	mock_token_idx = 0;

	/* Build a search chain: phrase "foo bar" AND before:2025 */
	struct mail_search_args *args = mail_search_build_init();

	/* Create the sibling criterion (SEARCH_BEFORE) */
	struct mail_search_arg *sibling = p_new(args->pool,
						struct mail_search_arg, 1);
	sibling->type = SEARCH_BEFORE;
	sibling->value.time = 1735689600; /* 2025-01-01 */

	/* Create the phrase arg with next pointing to sibling */
	struct mail_search_arg *phrase_arg = p_new(args->pool,
						   struct mail_search_arg, 1);
	phrase_arg->type = SEARCH_TEXT;
	phrase_arg->value.str = "foo bar";
	phrase_arg->next = sibling;

	args->args = phrase_arg;

	/* Expand the phrase arg */
	test_assert(fts_search_arg_expand(test_backend, args->pool,
						  &args->args) == 0);

	/* The expanded args should have next pointing to sibling
	   (preserved at the OR level). */
	struct mail_search_arg *arg_exp = args->args;
	test_assert(arg_exp->type == SEARCH_OR);
	test_assert(arg_exp->next == sibling);

	/* Inside the OR, the SUB's children should have no dangling
	   next. This is the key assertion: the phrase-full arg must
	   NOT have next pointing to the sibling (that's the bug
	   being fixed). */
	struct mail_search_arg *sub = arg_exp->value.subargs;
	test_assert(sub != NULL && sub->type == SEARCH_SUB);

	struct mail_search_arg *child = sub->value.subargs;
	while (child != NULL) {
		if (child->type == SEARCH_TEXT &&
		    HAS_ANY_BITS(child->value.search_flags,
				 MAIL_SEARCH_ARG_FLAG_PHRASE_FULL)) {
			test_assert(child->next == NULL);
		}

		child = child->next;
	}

	/* Verify simplify completes without hang/corruption */
	mail_search_args_simplify(args);

	/* After simplify, the sibling should still be reachable
	   somewhere in the tree. */
	arg_exp = args->args;
	test_assert(arg_exp != NULL);
	test_assert(sibling->next == NULL);

	mail_search_args_unref(&args);
}

static void test_phrase_with_sibling_next(void)
{
	test_begin("phrase with sibling next pointer");

	/* old (v1) args structure */
	test_backend->flags &= ~FTS_BACKEND_FLAG_SEARCH_ARGS_V2;
	test_phrase_with_sibling_next_helper();

	/* SEARCH_ARGS_V2 */
	test_backend->flags |= FTS_BACKEND_FLAG_SEARCH_ARGS_V2;
	test_phrase_with_sibling_next_helper();

	test_end();
}

static void test_create_or_next_pointer(void)
{
	test_begin("fts_search_arg_create_or next pointer correctness");

	/* This test verifies that fts_search_arg_create_or() correctly clears
	   the next pointer on copied args, matching the fix for the phrase
	   search path. */

	unsigned int i;
	struct mail_search_args *args = mail_search_build_init();

	/* Create an orig arg with a next pointer (simulating a sibling) */
	struct mail_search_arg *sibling = p_new(args->pool,
							struct mail_search_arg, 1);
	sibling->type = SEARCH_BEFORE;
	sibling->value.time = 1735689600;

	struct mail_search_arg *orig_arg = p_new(args->pool,
							 struct mail_search_arg, 1);
	orig_arg->type = SEARCH_TEXT;
	orig_arg->value.str = "test phrase";
	orig_arg->next = sibling;

	/* Create token array */
	ARRAY_TYPE(const_string) tokens;
	const char *strs[] = { "bar", "foo", "test phrase" };
	t_array_init(&tokens, 3);
	for (i = 0; i < 3; i++)
		array_append(&tokens, &strs[i], 1);

	/* Call fts_search_arg_create_or */
	struct mail_search_arg *or_arg = fts_search_arg_create_or(orig_arg,
								   args->pool, &tokens);

	/* The OR should NOT have the sibling as next */
	test_assert(or_arg->next == NULL);

	/* Walk the OR's child chain and verify no child points to sibling */
	struct mail_search_arg *child = or_arg->value.subargs;
	while (child != NULL) {
		test_assert(child->next != sibling);
		child = child->next;
	}

	/* The sibling should still be intact and separate */
	test_assert(sibling->next == NULL);
	test_assert(sibling->type == SEARCH_BEFORE);

	mail_search_args_unref(&args);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_setup,
		test_single_word,
		test_phrase_old_args_structure,
		test_phrase_new_args_structure,
		test_phrase_with_tab_whitespace,
		test_three_word_phrase,
		test_single_word_split,
		test_phrase_with_sibling_next,
		test_create_or_next_pointer,
		test_teardown,
		NULL
	};
	return test_run(test_functions);
}
