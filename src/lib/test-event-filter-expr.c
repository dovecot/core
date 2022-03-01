/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "strescape.h"
#include "event-filter.h"
#include "event-filter-private.h"

#define STRING1	"X"
#define STRING2	"Y"

/* dummy values, at least for now */
#define SOURCE_FILENAME "blah.c"
#define SOURCE_LINE 123

static void check_expr(const char *test_name,
		       struct event *event,
		       struct event_filter *filter,
		       enum event_filter_log_type log_type,
		       bool expected)
{
	struct event_filter_node *expr;
	unsigned int num_queries;
	bool got;

	/* get at the expr inside the filter */
	expr = event_filter_get_expr_for_testing(filter, &num_queries);
	test_out_quiet(t_strdup_printf("%s:num_queries==1", test_name),
		       num_queries == 1); /* should have only one query */

	got = event_filter_query_match_eval(expr, event,
					    SOURCE_FILENAME, SOURCE_LINE,
					    log_type);
	test_out_quiet(t_strdup_printf("%s:got=expected", test_name),
		       got == expected);
}

static void do_test_expr(const char *filter_string, struct event *event,
			 enum event_filter_log_type log_type,
			 bool expected)
{
	const char *test_name, *error;

	test_name = t_strdup_printf(
		"%.*s log type + event {a=%s, b=%s} + filter '%s' (exp %s)",
		3, /* truncate the type name to avoid CI seeing 'warning' messages */
		event_filter_category_from_log_type(log_type),
		event_find_field_recursive_str(event, "a"),
		event_find_field_recursive_str(event, "b"),
		filter_string,
		expected ? "true" : "false");

	/* set up the filter expression */
	struct event_filter *filter = event_filter_create();
	test_out_quiet(t_strdup_printf("%s:event_filter_parse()", test_name),
		       event_filter_parse(filter_string, filter, &error) == 0);

	check_expr(test_name, event, filter, log_type, expected);

	event_filter_unref(&filter);
}

static void test_unary_expr(struct event *event,
			    const char *expr, bool truth,
			    enum event_filter_log_type log_type)
{
	/*
	 * The UNARY() macro checks:
	 *
	 * 1. expr
	 * 2. NOT expr
	 * 3. NOT (expr)
	 *
	 * Note that numbers 2 and 3 are equivalent.
	 *
	 * The truth argument specifies the expected truth-iness of the
	 * passed in expression.
	 */
#define UNARY()								\
	T_BEGIN {							\
		do_test_expr(expr,					\
			     event, log_type, truth);			\
		do_test_expr(t_strdup_printf("NOT %s", expr),		\
			     event, log_type, !truth);			\
		do_test_expr(t_strdup_printf("NOT (%s)", expr),		\
			     event, log_type, !truth);			\
	} T_END

	UNARY();
}

static void test_binary_expr(struct event *event,
			     const char *expr1, const char *expr2,
			     bool truth1, bool truth2,
			     enum event_filter_log_type log_type)
{
	/*
	 * The BINARY() macro checks:
	 *
	 * 1. expr1 op expr2
	 * 2. NOT expr1 op expr2
	 * 3. NOT (expr1) op expr2
	 * 4. (NOT expr1) op expr2
	 * 5. expr1 op NOT expr2
	 * 6. expr1 op NOT (expr2)
	 * 7. expr1 op (NOT expr2)
	 * 8. NOT (expr1 op expr2)
	 * 9. NOT expr1 op NOT expr2
	 * 10. NOT (expr1) op NOT (expr2)
	 * 11. (NOT expr1) op (NOT expr2)
	 *
	 * Where op is OR or AND.
	 *
	 * Note that:
	 *  - numbers 2, 3, and 4 are equivalent
	 *  - numbers 5, 6, and 7 are equivalent
	 *  - numbers 9, 10, and 11 are equivalent
	 *
	 * The truth arugments specify the expected truth-iness of the
	 * passed in expressions.
	 */
#define BINARY(opstr, op)						\
	T_BEGIN {							\
		do_test_expr(t_strdup_printf("%s %s %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     (truth1) op (truth2));			\
		do_test_expr(t_strdup_printf("NOT %s %s %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op (truth2));			\
		do_test_expr(t_strdup_printf("NOT (%s) %s %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op (truth2));			\
		do_test_expr(t_strdup_printf("(NOT %s) %s %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op (truth2));			\
		do_test_expr(t_strdup_printf("%s %s NOT %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     (truth1) op !(truth2));			\
		do_test_expr(t_strdup_printf("%s %s NOT (%s)", expr1, opstr, expr2),\
			     event, log_type,				\
			     (truth1) op !(truth2));			\
		do_test_expr(t_strdup_printf("%s %s (NOT %s)", expr1, opstr, expr2),\
			     event, log_type,				\
			     (truth1) op !(truth2));			\
		do_test_expr(t_strdup_printf("NOT (%s %s %s)", expr1, opstr, expr2),\
			     event, log_type,				\
			     !((truth1) op (truth2)));			\
		do_test_expr(t_strdup_printf("NOT %s %s NOT %s", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op !(truth2));			\
		do_test_expr(t_strdup_printf("NOT (%s) %s NOT (%s)", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op !(truth2));			\
		do_test_expr(t_strdup_printf("(NOT %s) %s (NOT %s)", expr1, opstr, expr2),\
			     event, log_type,				\
			     !(truth1) op !(truth2));			\
	} T_END

	BINARY("OR", ||);
	BINARY("AND", &&);
}

static void test_event_filter_expr_fields(enum event_filter_log_type log_type)
{
	static const char *values[] = {
		NULL,
		"",
		STRING1,
		STRING2,
	};
	unsigned int a, b;

#define STR_IS_EMPTY(v) \
		(((v) == NULL) || (strcmp("", (v)) == 0))
#define STR_MATCHES(v, c) \
		(((v) != NULL) && (strcmp((c), (v)) == 0))

	/* unary */
	for (a = 0; a < N_ELEMENTS(values); a++) {
		/* set up the event to match against */
		struct event *event = event_create(NULL);
		event_add_str(event, "a", values[a]);

		test_unary_expr(event,
				"a=\"\"",
				STR_IS_EMPTY(values[a]),
				log_type);
		test_unary_expr(event,
				"a=" STRING1,
				STR_MATCHES(values[a], STRING1),
				log_type);

		event_unref(&event);
	}

	/* binary */
	for (a = 0; a < N_ELEMENTS(values); a++) {
		for (b = 0; b < N_ELEMENTS(values); b++) {
			/* set up the event to match against */
			struct event *event = event_create(NULL);
			event_add_str(event, "a", values[a]);
			event_add_str(event, "b", values[b]);

			test_binary_expr(event,
					 "a=\"\"",
					 "b=\"\"",
					 STR_IS_EMPTY(values[a]),
					 STR_IS_EMPTY(values[b]),
					 log_type);
			test_binary_expr(event,
					 "a=" STRING1,
					 "b=\"\"",
					 STR_MATCHES(values[a], STRING1),
					 STR_IS_EMPTY(values[b]),
					 log_type);
			test_binary_expr(event,
					 "a=\"\"",
					 "b=" STRING2,
					 STR_IS_EMPTY(values[a]),
					 STR_MATCHES(values[b], STRING2),
					 log_type);
			test_binary_expr(event,
					 "a=" STRING1,
					 "b=" STRING2,
					 STR_MATCHES(values[a], STRING1),
					 STR_MATCHES(values[b], STRING2),
					 log_type);

			event_unref(&event);
		}
	}
}

void test_event_filter_expr(void)
{
	static const enum event_filter_log_type log_types[] = {
		EVENT_FILTER_LOG_TYPE_DEBUG,
		EVENT_FILTER_LOG_TYPE_INFO,
		EVENT_FILTER_LOG_TYPE_WARNING,
		EVENT_FILTER_LOG_TYPE_ERROR,
		EVENT_FILTER_LOG_TYPE_FATAL,
		EVENT_FILTER_LOG_TYPE_PANIC,
	};
	unsigned int i;

	test_begin("event filter expressions");
	for (i = 0; i < N_ELEMENTS(log_types); i++)
		test_event_filter_expr_fields(log_types[i]);
	test_end();
}
