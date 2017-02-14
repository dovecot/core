/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"

static void test_p_strarray_dup(void)
{
	const char *input[][3] = {
		{ NULL },
		{ "a", NULL },
		{ "foobar", NULL },
		{ "a", "foo", NULL }
	};
	const char **ret;
	unsigned int i, j;

	test_begin("p_strarray_dup");

	for (i = 0; i < N_ELEMENTS(input); i++) {
		ret = p_strarray_dup(default_pool, input[i]);
		for (j = 0; input[i][j] != NULL; j++) {
			test_assert(strcmp(input[i][j], ret[j]) == 0);
			test_assert(input[i][j] != ret[j]);
		}
		test_assert(ret[j] == NULL);
		i_free(ret);
	}
	test_end();
}

static void test_t_strsplit(void)
{
	const char *const *args;

	test_begin("t_strsplit");
	/* empty string -> empty array. was this perhaps a mistake for the
	   API to do this originally?.. can't really change now anyway. */
	args = t_strsplit("", "\n");
	test_assert(args[0] == NULL);
	/* two empty strings */
	args = t_strsplit("\n", "\n");
	test_assert(args[0][0] == '\0');
	test_assert(args[1][0] == '\0');
	test_assert(args[2] == NULL);
	test_end();
}

static void test_t_strsplit_spaces(void)
{
	const char *const *args;

	test_begin("t_strsplit_spaces");
	/* empty strings */
	args = t_strsplit_spaces("", "\n");
	test_assert(args[0] == NULL);
	args = t_strsplit_spaces("\n", "\n");
	test_assert(args[0] == NULL);
	args = t_strsplit_spaces("\n\n", "\n");
	test_assert(args[0] == NULL);

	/* multiple separators */
	args = t_strsplit_spaces(" , ,   ,str1  ,  ,,, , str2   , ", " ,");
	test_assert(strcmp(args[0], "str1") == 0);
	test_assert(strcmp(args[1], "str2") == 0);
	test_assert(args[2] == NULL);
	test_end();
}

static void test_t_str_replace(void)
{
	test_begin("t_str_replace");
	test_assert(strcmp(t_str_replace("foo", 'a', 'b'), "foo") == 0);
	test_assert(strcmp(t_str_replace("fooa", 'a', 'b'), "foob") == 0);
	test_assert(strcmp(t_str_replace("afooa", 'a', 'b'), "bfoob") == 0);
	test_assert(strcmp(t_str_replace("", 'a', 'b'), "") == 0);
	test_assert(strcmp(t_str_replace("a", 'a', 'b'), "b") == 0);
	test_assert(strcmp(t_str_replace("aaa", 'a', 'b'), "bbb") == 0);
	test_assert(strcmp(t_str_replace("bbb", 'a', 'b'), "bbb") == 0);
	test_assert(strcmp(t_str_replace("aba", 'a', 'b'), "bbb") == 0);
	test_end();
}

static void test_t_str_trim(void)
{
	test_begin("t_str_trim");
	test_assert(strcmp(t_str_trim("", " "), "") == 0);
	test_assert(strcmp(t_str_trim(" ", " "), "") == 0);
	test_assert(strcmp(t_str_trim(" \t ", "\t "), "") == 0);
	test_assert(strcmp(t_str_trim("f \t ", "\t "), "f") == 0);
	test_assert(strcmp(t_str_trim("foo", ""), "foo") == 0);
	test_assert(strcmp(t_str_trim("foo", " "), "foo") == 0);
	test_assert(strcmp(t_str_trim("foo ", " "), "foo") == 0);
	test_assert(strcmp(t_str_trim(" foo", " "), "foo") == 0);
	test_assert(strcmp(t_str_trim(" foo ", " "), "foo") == 0);
	test_assert(strcmp(t_str_trim("\tfoo ", "\t "), "foo") == 0);
	test_assert(strcmp(t_str_trim(" \tfoo\t ", "\t "), "foo") == 0);
	test_assert(strcmp(t_str_trim("\r \tfoo\t \r", "\t \r"), "foo") == 0);
	test_assert(strcmp(t_str_trim("\r \tfoo foo\t \r", "\t \r"), "foo foo") == 0);
	test_assert(strcmp(t_str_trim("\tfoo\tfoo\t", "\t \r"), "foo\tfoo") == 0);
	test_end();
}

static void test_t_str_ltrim(void)
{
	test_begin("t_str_ltrim");
	test_assert(strcmp(t_str_ltrim("", " "), "") == 0);
	test_assert(strcmp(t_str_ltrim(" ", " "), "") == 0);
	test_assert(strcmp(t_str_ltrim(" \t ", "\t "), "") == 0);
	test_assert(strcmp(t_str_ltrim(" \t f", "\t "), "f") == 0);
	test_assert(strcmp(t_str_ltrim("foo", ""), "foo") == 0);
	test_assert(strcmp(t_str_ltrim("foo", " "), "foo") == 0);
	test_assert(strcmp(t_str_ltrim("foo ", " "), "foo ") == 0);
	test_assert(strcmp(t_str_ltrim(" foo", " "), "foo") == 0);
	test_assert(strcmp(t_str_ltrim(" foo ", " "), "foo ") == 0);
	test_assert(strcmp(t_str_ltrim("\tfoo ", "\t "), "foo ") == 0);
	test_assert(strcmp(t_str_ltrim(" \tfoo\t ", "\t "), "foo\t ") == 0);
	test_assert(strcmp(t_str_ltrim("\r \tfoo\t \r", "\t \r"), "foo\t \r") == 0);
	test_assert(strcmp(t_str_ltrim("\r \tfoo foo\t \r", "\t \r"), "foo foo\t \r") == 0);
	test_assert(strcmp(t_str_ltrim("\tfoo\tfoo\t", "\t \r"), "foo\tfoo\t") == 0);
	test_end();
}

static void test_t_str_rtrim(void)
{
	test_begin("t_str_rtrim");
	test_assert(strcmp(t_str_rtrim("", " "), "") == 0);
	test_assert(strcmp(t_str_rtrim(" ", " "), "") == 0);
	test_assert(strcmp(t_str_rtrim(" \t ", "\t "), "") == 0);
	test_assert(strcmp(t_str_rtrim("f \t ", "\t "), "f") == 0);
	test_assert(strcmp(t_str_rtrim("foo", ""), "foo") == 0);
	test_assert(strcmp(t_str_rtrim("foo", " "), "foo") == 0);
	test_assert(strcmp(t_str_rtrim("foo ", " "), "foo") == 0);
	test_assert(strcmp(t_str_rtrim(" foo", " "), " foo") == 0);
	test_assert(strcmp(t_str_rtrim(" foo ", " "), " foo") == 0);
	test_assert(strcmp(t_str_rtrim("\tfoo ", "\t "), "\tfoo") == 0);
	test_assert(strcmp(t_str_rtrim(" \tfoo\t ", "\t "), " \tfoo") == 0);
	test_assert(strcmp(t_str_rtrim("\r \tfoo\t \r", "\t \r"), "\r \tfoo") == 0);
	test_assert(strcmp(t_str_rtrim("\r \tfoo foo\t \r", "\t \r"), "\r \tfoo foo") == 0);
	test_assert(strcmp(t_str_rtrim("\tfoo\tfoo\t", "\t \r"), "\tfoo\tfoo") == 0);
	test_end();
}

static const char *const test_strarray_input[] = {
	"", "hello", "world", "", "yay", "", NULL
};
static const struct {
	const char *separator;
	const char *output;
} test_strarray_outputs[] = {
	{ "", "helloworldyay" },
	{ " ", " hello world  yay " },
	{ "!-?", "!-?hello!-?world!-?!-?yay!-?" }
};

static const char *const test_strarray_input2[] = {
	"", "", "hello", "world", "", "yay", "", NULL
};
static struct {
	const char *separator;
	const char *output;
} test_strarray_outputs2[] = {
	{ "", "helloworldyay" },
	{ " ", "  hello world  yay " },
	{ "!-?", "!-?!-?hello!-?world!-?!-?yay!-?" }
};

static const char *const test_strarray_input3[] = {
	"hello", "", "", "yay", NULL
};
static struct {
	const char *separator;
	const char *output;
} test_strarray_outputs3[] = {
	{ "", "helloyay" },
	{ " ", "hello   yay" },
	{ "!-?", "hello!-?!-?!-?yay" }
};

static void test_t_strarray_join(void)
{
	const char *null = NULL;
	unsigned int i;

	test_begin("t_strarray_join()");

	/* empty array -> empty string */
	test_assert(strcmp(t_strarray_join(&null, " "), "") == 0);

	for (i = 0; i < N_ELEMENTS(test_strarray_outputs); i++) {
		test_assert_idx(strcmp(t_strarray_join(test_strarray_input,
						       test_strarray_outputs[i].separator),
				       test_strarray_outputs[i].output) == 0, i);
	}
	for (i = 0; i < N_ELEMENTS(test_strarray_outputs2); i++) {
		test_assert_idx(strcmp(t_strarray_join(test_strarray_input2,
						       test_strarray_outputs2[i].separator),
				       test_strarray_outputs2[i].output) == 0, i);
	}
	for (i = 0; i < N_ELEMENTS(test_strarray_outputs3); i++) {
		test_assert_idx(strcmp(t_strarray_join(test_strarray_input3,
						       test_strarray_outputs3[i].separator),
				       test_strarray_outputs3[i].output) == 0, i);
	}
	test_end();
}

static void test_p_array_const_string_join(void)
{
	ARRAY_TYPE(const_string) arr;
	unsigned int i;
	char *res;

	test_begin("p_array_const_string_join()");

	i_array_init(&arr, 2);
	/* empty array -> empty string */
	test_assert(strcmp(t_array_const_string_join(&arr, " "), "") == 0);

	array_append(&arr, test_strarray_input,
		     str_array_length(test_strarray_input));
	for (i = 0; i < N_ELEMENTS(test_strarray_outputs); i++) {
		res = p_array_const_string_join(default_pool, &arr,
						test_strarray_outputs[i].separator);
		test_assert_idx(strcmp(res, test_strarray_outputs[i].output) == 0, i);
		i_free(res);
	}

	array_free(&arr);
	test_end();
}

void test_strfuncs(void)
{
	test_p_strarray_dup();
	test_t_strsplit();
	test_t_strsplit_spaces();
	test_t_str_replace();
	test_t_str_trim();
	test_t_str_ltrim();
	test_t_str_rtrim();
	test_t_strarray_join();
	test_p_array_const_string_join();
}
