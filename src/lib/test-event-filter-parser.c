/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "strescape.h"
#include "event-filter.h"

#define GOOD(i, o)	\
	{ \
		.input = (i), \
		.output = (o), \
		.fails = FALSE, \
	}

#define BAD(i, o)	\
	{ \
		.input = (i), \
		.output = (o), \
		.fails = TRUE, \
	}

enum quoting {
	QUOTE_MUST,
	QUOTE_MAY,
	QUOTE_MUST_NOT,
};

static const char *what_special[] = {
	"event",
	"category",
	"source_location",
};

/* some sample field names */
static const char *what_fields_single[] = {
	"foo",
	"foo_bar",
	"foo-bar",
};

static const char *comparators[] = {
	"=",
	"<",
	"<=",
	">",
	">=",
};

/* values that may be quoted or not quoted */
static const char *values_single[] = {
	"foo",
	"foo.c",
	"foo.c:123",
};

/* values that need to be quoted */
static const char *values_multi[] = {
	"foo bar",
	"foo\tbar",
	"foo\nbar",
	"foo\rbar",
	"foo\"bar",
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec ac "
	"vestibulum magna. Maecenas erat mi, finibus et tellus id, suscipit "
	"varius arcu. Morbi faucibus diam in ligula suscipit, non bibendum "
	"orci venenatis. Vestibulum mattis luctus dictum.  Vivamus ultrices "
	"tincidunt vehicula. Aliquam nec ante vitae libero dignissim finibus "
	"non ac massa. Proin sit amet semper ligula. Curabitur eleifend massa "
	"et arcu euismod lacinia.  Phasellus sapien mauris, dignissim vitae "
	"commodo at, consequat eget augue. Integer posuere non enim eu "
	"laoreet. Nulla eget lectus at enim sodales rutrum. Donec tincidunt "
	"nibh ac convallis pulvinar. Nunc facilisis tempus ligula. Nullam at "
	"ultrices enim, eu faucibus ipsum."
	/* utf-8: >= U+128 only */
	"\xc3\xa4\xc3\xa1\xc4\x8d\xc4\x8f\xc4\x9b\xc5\x88\xc3\xb6\xc5\x99\xc3\xbc\xc3\xba\xc5\xaf",
	/* utf-8: ascii + combining char */
	"r\xcc\x8c",
};

/* boolean operators used as values get lowercased unless they are quoted */
static const struct values_oper {
	const char *in;
	const char *out_unquoted;
	const char *out_quoted;
} values_oper[] = {
	{ "AND", "and", "AND" },
	{ "ANd", "and", "ANd" },
	{ "AnD", "and", "AnD" },
	{ "And", "and", "And" },
	{ "aND", "and", "aND" },
	{ "aNd", "and", "aNd" },
	{ "anD", "and", "anD" },
	{ "and", "and", "and" },

	{ "OR", "or", "OR" },
	{ "Or", "or", "Or" },
	{ "oR", "or", "oR" },
	{ "or", "or", "or" },

	{ "NOT", "not", "NOT" },
	{ "NOt", "not", "NOt" },
	{ "NoT", "not", "NoT" },
	{ "Not", "not", "Not" },
	{ "nOT", "not", "nOT" },
	{ "nOt", "not", "nOt" },
	{ "noT", "not", "noT" },
	{ "not", "not", "not" },
};

static struct test {
	const char *input;
	const char *output;
	bool fails;
} tests[] = {
	GOOD("", ""),

	/* check that spaces and extra parens don't break anything */
#define CHECK_REAL(sp1, key, sp2, sp3, value, sp4) \
	GOOD(sp1 key sp2 "=" sp3 value sp4, \
	     "(" key "=\"" value "\")")
#define CHECK_SPACES(key, value, sp, op, cp) \
	CHECK_REAL(sp op, key, "", "", value, "" cp), \
	CHECK_REAL(op sp, key, "", "", value, "" cp), \
	CHECK_REAL(op "", key, sp, "", value, "" cp), \
	CHECK_REAL(op "", key, "", sp, value, "" cp), \
	CHECK_REAL(op "", key, "", "", value, sp cp), \
	CHECK_REAL(op "", key, "", "", value, cp sp)
#define CHECK_PARENS(key, value, sp) \
	CHECK_SPACES(key, value, sp, "", ""), \
	CHECK_SPACES(key, value, sp, "(", ")"), \
	CHECK_SPACES(key, value, sp, "((", "))"), \
	CHECK_SPACES(key, value, sp, "(((", ")))")

	CHECK_PARENS("event", "abc", " "),
	CHECK_PARENS("event", "abc", "\t"),
	CHECK_PARENS("event", "abc", "\n"),
	CHECK_PARENS("event", "abc", "\r"),
	CHECK_PARENS("event", "abc", "          "),
#undef CHECK_PARENS
#undef CHECK_SPACES
#undef CHECK_REAL

	/* check empty parens */
	BAD("()",
	    "event filter: syntax error, unexpected ')', expecting TOKEN or STRING or NOT or '('"),

	/* check name only / name+comparator (!negated & negated) */
#define CHECK_CMP_REAL(not, name, cmp, err) \
	BAD(not name cmp, err), \
	BAD(not "\"" name "\"" cmp, err)
#define CHECK_CMP(name, cmp, err) \
	CHECK_CMP_REAL("", name, cmp, err), \
	CHECK_CMP_REAL("NOT ", name, cmp, err)
#define CHECK(name) \
	CHECK_CMP(name, "", \
	    "event filter: syntax error, unexpected $end, expecting '=' or '>' or '<'"), \
	CHECK_CMP(name, "=", \
	    "event filter: syntax error, unexpected $end"), \
	CHECK_CMP(name, "<", \
	    "event filter: syntax error, unexpected $end"), \
	CHECK_CMP(name, "<=", \
	    "event filter: syntax error, unexpected $end"), \
	CHECK_CMP(name, ">", \
	    "event filter: syntax error, unexpected $end"), \
	CHECK_CMP(name, ">=", \
	    "event filter: syntax error, unexpected $end")

	CHECK("event"),
	CHECK("source_location"),
	CHECK("category"),
	CHECK("foo-field-name"),
#undef CHECK
#undef CHECK_CMP
#undef CHECK_CMP_REAL

	/* check simple nesting */
#define CHECK(binop1, binop2) \
	GOOD("(event=abc " binop1 " event=def) " binop2 " event=ghi", \
	     "(((event=\"abc\" " binop1 " event=\"def\") " binop2 " event=\"ghi\"))"), \
	GOOD("event=abc " binop1 " (event=def " binop2 " event=ghi)", \
	     "((event=\"abc\" " binop1 " (event=\"def\" " binop2 " event=\"ghi\")))")

	CHECK("AND", "AND"),
	CHECK("AND", "OR"),
	CHECK("OR", "AND"),
	CHECK("OR", "OR"),
#undef CHECK

	/* check operator precedence */
#define CMP(x) "event=\"" #x "\""
#define CHECK(binop1, binop2) \
	GOOD(CMP(1) " " binop1 " " CMP(2) " " binop2 " " CMP(3), \
	"(((" CMP(1) " " binop1 " " CMP(2) ") " binop2 " " CMP(3) "))")

	CHECK("AND", "AND"),
	CHECK("AND", "OR"),
	CHECK("OR", "AND"),
	CHECK("OR", "OR"),
#undef CHECK
#undef CMP
};

static void testcase(const char *name, const char *input, const char *exp,
		     bool fails)
{
	struct event_filter *filter;
	const char *error;
	const char *got;
	int ret;

	test_begin(t_strdup_printf("event filter parser: %s: %s", name, input));

	filter = event_filter_create();
	ret = event_filter_parse(input, filter, &error);

	test_assert((ret != 0) == fails);

	if (ret == 0) {
		string_t *tmp = t_str_new(128);

		event_filter_export(filter, tmp);

		got = str_c(tmp);
	} else {
		got = error;
	}

	test_assert_strcmp(exp, got);

	test_end();
}

static void test_event_filter_parser_table(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		testcase("table",
			 tests[i].input,
			 tests[i].output,
			 tests[i].fails);
	} T_END;
}

static void test_event_filter_parser_categories(void)
{
	static const char *cat_names[] = {
		"debug", "info", "warning", "error", "fatal", "panic",
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cat_names); i++) T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "(category=");
		str_append(str, cat_names[i]);
		str_append(str, ")");

		testcase("log type category", str_c(str), str_c(str), FALSE);
	} T_END;
}

static void
test_event_filter_parser_simple_nesting_helper(bool not1, bool not2,
					       bool and, const char *sp,
					       bool sp1, bool sp2,
					       bool sp3, bool sp4)
{
	const char *op = and ? "AND" : "OR";
	const char *expr1 = "event=\"abc\"";
	const char *expr2 = "event=\"def\"";
	const char *in;
	const char *exp;

	in = t_strdup_printf("%s(%s%s)%s%s%s(%s%s)%s",
			     sp1 ? sp : "",
			     not1 ? "NOT " : "",
			     expr1,
			     sp2 ? sp : "",
			     op,
			     sp3 ? sp : "",
			     not2 ? "NOT " : "",
			     expr2,
			     sp4 ? sp : "");

	exp = t_strdup_printf("((%s%s%s %s %s%s%s))",
			      not1 ? "(NOT " : "",
			      expr1,
			      not1 ? ")" : "",
			      op,
			      not2 ? "(NOT " : "",
			      expr2,
			      not2 ? ")" : "");

	testcase("simple nesting", in, exp, FALSE);
}

static void test_event_filter_parser_simple_nesting(void)
{
	const char *whitespace[] = {
		"",
		"\t",
		"\n",
		"\r",
		"               ",
	};
	unsigned int i;
	unsigned int loc;
	unsigned int not;

	for (i = 0; i < N_ELEMENTS(whitespace); i++) {
		for (not = 0; not < 4; not++) {
			const bool not1 = (not & 0x2) != 0;
			const bool not2 = (not & 0x1) != 0;

			for (loc = 0; loc < 16; loc++) T_BEGIN {
				const bool sp1 = (loc & 0x8) != 0;
				const bool sp2 = (loc & 0x4) != 0;
				const bool sp3 = (loc & 0x2) != 0;
				const bool sp4 = (loc & 0x1) != 0;

				test_event_filter_parser_simple_nesting_helper(not1, not2,
									       TRUE,
									       whitespace[i],
									       sp1, sp2,
									       sp3, sp4);
				test_event_filter_parser_simple_nesting_helper(not1, not2,
									       FALSE,
									       whitespace[i],
									       sp1, sp2,
									       sp3, sp4);
			} T_END;
		}
	}
}

/*
 * Test '<key><op><value>' with each possible operator and each possible
 * quoting of <key> and <value>.  Some quotings are not allowed.  The keyq
 * and valueq arguments specify whether the <key> and <value> strings
 * should be quoted.
 */
static void generated_single_comparison(const char *name,
					bool parens,
					const char *key,
					enum quoting keyq,
					const char *value_in,
					const char *value_exp,
					enum quoting valueq)
{
	unsigned int c, q;

	for (c = 0; c < N_ELEMENTS(comparators); c++) {
		string_t *output = t_str_new(128);

		str_append_c(output, '(');
		if (keyq != QUOTE_MUST_NOT)
			str_append_c(output, '"');
		str_append(output, key);
		if (keyq != QUOTE_MUST_NOT)
			str_append_c(output, '"');
		str_append(output, comparators[c]);
		str_append_c(output, '"');
		str_append_escaped(output, value_exp, strlen(value_exp));
		str_append_c(output, '"');
		str_append_c(output, ')');

		for (q = 0; q < 4; q++) {
			const bool qkey = (q & 1) == 1;
			const bool qval = (q & 2) == 2;
			string_t *input = t_str_new(128);

			if ((!qkey && (keyq == QUOTE_MUST)) ||
			    (qkey && (keyq == QUOTE_MUST_NOT)))
				continue;
			if ((!qval && (valueq == QUOTE_MUST)) ||
			    (qval && (valueq == QUOTE_MUST_NOT)))
				continue;

			if (parens)
				str_append_c(input, '(');
			if (qkey)
				str_append_c(input, '"');
			str_append(input, key);
			if (qkey)
				str_append_c(input, '"');
			str_append(input, comparators[c]);
			if (qval) {
				str_append_c(input, '"');
				str_append_escaped(input, value_in, strlen(value_in));
				str_append_c(input, '"');
			} else {
				str_append(input, value_in);
			}
			if (parens)
				str_append_c(input, ')');

			testcase(name,
				 str_c(input),
				 str_c(output),
				 FALSE);
		}
	}
}

static void test_event_filter_parser_generated(bool parens)
{
	unsigned int w, v;

	/* check that non-field keys work */
	for (w = 0; w < N_ELEMENTS(what_special); w++) {
		for (v = 0; v < N_ELEMENTS(values_single); v++)
			generated_single_comparison("non-field/single",
						    parens,
						    what_special[w],
						    QUOTE_MUST_NOT,
						    values_single[v],
						    values_single[v],
						    QUOTE_MAY);

		for (v = 0; v < N_ELEMENTS(values_multi); v++)
			generated_single_comparison("non-field/multi",
						    parens,
						    what_special[w],
						    QUOTE_MUST_NOT,
						    values_multi[v],
						    values_multi[v],
						    QUOTE_MUST);

		for (v = 0; v < N_ELEMENTS(values_oper); v++) {
			generated_single_comparison("non-field/bool-op",
						    parens,
						    what_special[w],
						    QUOTE_MUST_NOT,
						    values_oper[v].in,
						    values_oper[v].out_unquoted,
						    QUOTE_MUST_NOT);
			generated_single_comparison("non-field/bool-op",
						    parens,
						    what_special[w],
						    QUOTE_MUST_NOT,
						    values_oper[v].in,
						    values_oper[v].out_quoted,
						    QUOTE_MUST);
		}
	}

	/* check that field keys work */
	for (w = 0; w < N_ELEMENTS(what_fields_single); w++) {
		for (v = 0; v < N_ELEMENTS(values_single); v++)
			generated_single_comparison("field/single",
						    parens,
						    what_fields_single[w],
						    QUOTE_MAY,
						    values_single[v],
						    values_single[v],
						    QUOTE_MAY);

		for (v = 0; v < N_ELEMENTS(values_multi); v++)
			generated_single_comparison("field/multi",
						    parens,
						    what_fields_single[w],
						    QUOTE_MAY,
						    values_multi[v],
						    values_multi[v],
						    QUOTE_MUST);

		for (v = 0; v < N_ELEMENTS(values_oper); v++) {
			generated_single_comparison("field/bool-op",
						    parens,
						    what_fields_single[w],
						    QUOTE_MAY,
						    values_oper[v].in,
						    values_oper[v].out_unquoted,
						    QUOTE_MUST_NOT);
			generated_single_comparison("field/bool-op",
						    parens,
						    what_fields_single[w],
						    QUOTE_MAY,
						    values_oper[v].in,
						    values_oper[v].out_quoted,
						    QUOTE_MUST);
		}
	}
}

void test_event_filter_parser(void)
{
	test_event_filter_parser_table();
	test_event_filter_parser_categories();
	test_event_filter_parser_simple_nesting();
	test_event_filter_parser_generated(FALSE);
	test_event_filter_parser_generated(TRUE);
}
