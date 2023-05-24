/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-event-private.h"
#include "str.h"
#include "ioloop.h"
#include "stats-client.h"
#include "test-common.h"

#define TST_BEGIN(test_name)				\
	test_begin(test_name);				\
	ioloop_timeval.tv_sec = 0;			\
	ioloop_timeval.tv_usec = 0;

static struct event_category test_cats[5] = {
	{.name = "test1"},
	{.name = "test2"},
	{.name = "test3"},
	{.name = "test4"},
	{.name = "test5"},
};

static struct event_field test_fields[5] = {
	{.key = "key1",
	 .value_type = EVENT_FIELD_VALUE_TYPE_STR,
	 .value = {.str = "str1"}},

	{.key = "key2",
	 .value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
	 .value = {.intmax = 20}},

	{.key = "key3",
	 .value_type = EVENT_FIELD_VALUE_TYPE_TIMEVAL,
	 .value = {.timeval = {.tv_sec = 10}}},

	{.key = "key4",
	 .value = {.str = "str4"}},

	{.key = "key5",
	 .value = {.intmax = 50}},
};

static string_t *stats_buf;

static bool compare_test_stats_data_line(const char *reference, const char *actual)
{
	const char *const *ref_args = t_strsplit(reference, "\t");
	const char *const *act_args = t_strsplit(actual, "\t");
	unsigned int max = str_array_length(ref_args);

	/* different lengths imply not equal */
	if (str_array_length(ref_args) != str_array_length(act_args))
		return FALSE;

	for (size_t i = 0; i < max; i++) {
		if (i > 1 && i < 6) continue;
		if (*(ref_args[i]) == 'l') {
			i++;
			continue;
		}
		if (strcmp(ref_args[i], act_args[i]) != 0) {
			return FALSE;
		}
	}
	return TRUE;
}

static bool compare_test_stats_data_lines(const char *actual, const char *reference)
{
	const char *const *lines_ref = t_strsplit(reference, "\n");
	const char *const *lines_act = t_strsplit(actual, "\n");
	for(; *lines_ref != NULL && *lines_act != NULL; lines_ref++, lines_act++) {
		if (!compare_test_stats_data_line(*lines_ref, *lines_act))
			return FALSE;
	}
	return *lines_ref == *lines_act;
}

static bool ATTR_FORMAT(1, 2)
compare_test_stats_to(const char *format, ...)
{
	bool res;
	string_t *reference = t_str_new(1024);
	va_list args;
	va_start (args, format);
	str_vprintfa (reference, format, args);
	va_end (args);

	res = compare_test_stats_data_lines(str_c(stats_buf), str_c(reference));
	str_truncate(stats_buf, 0);
	return res;
}

static void test_fail_callback(const struct failure_context *ctx ATTR_UNUSED,
			       const char *format ATTR_UNUSED,
			       va_list args ATTR_UNUSED)
{
	/* ignore message, all we need is stats */
}

static void register_all_categories(void)
{
	/* Run this before all the tests,
	   so stats client doesn't send CATEGORY\ttestx anymore,
	   so test will produce stats records independent of test order */
	struct event *ev;
	int i;
	for (i = 0; i < 5; i++) {
		ev = event_create(NULL);
		event_add_category(ev, &test_cats[i]);
		e_info(ev, "message");
		event_unref(&ev);
	}
}

static void test_no_merging1(void)
{
	/* NULL parent */
	int l;
	TST_BEGIN("no merging parent is NULL");
	struct event *single_ev = event_create(NULL);
	event_add_category(single_ev, &test_cats[0]);
	event_add_str(single_ev, test_fields[0].key, test_fields[0].value.str);
	event_set_name(single_ev, "evname");
	e_info(single_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&single_ev);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	0	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	nevname	ctest1	Skey1	str1\n", l));
	test_end();
}

static void test_no_merging2(void)
{
	/* Parent sent to stats */
	int l;
	uint64_t id;
	TST_BEGIN("no merging parent sent to stats");
	struct event *parent_ev = event_create(NULL);
	event_add_category(parent_ev, &test_cats[0]);
	parent_ev->sent_to_stats_id = parent_ev->change_id;
	id = parent_ev->id;
	struct event *child_ev = event_create(parent_ev);
	event_add_category(child_ev, &test_cats[1]);
	event_set_name(child_ev, "evname");
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_ev);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	nevname	ctest2\n"
			"END	8\n", id, l));
	test_end();
}

static void test_no_merging3(void)
{
	/* Parent have different timestamp */
	int l, lp;
	uint64_t idp;
	TST_BEGIN("no merging parent timestamp differs");
	struct event *parent_ev = event_create(NULL);
	lp = __LINE__ - 1;
	idp = parent_ev->id;
	event_add_category(parent_ev, &test_cats[0]);
	parent_ev->sent_to_stats_id = 0;
	ioloop_timeval.tv_sec++;
	struct event *child_ev = event_create(parent_ev);
	event_add_category(child_ev, &test_cats[1]);
	event_set_name(child_ev, "evname");
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_ev);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest2\n"
			"END\t%"PRIu64"\n", idp, lp, idp, l, idp));
	test_end();
}

static void test_merge_events1(void)
{
	int l;
	TST_BEGIN("merge events parent NULL");
	struct event *merge_ev1 = event_create(NULL);
	event_add_category(merge_ev1, &test_cats[0]);
	event_add_category(merge_ev1, &test_cats[1]);
	event_add_str(merge_ev1,test_fields[0].key, test_fields[0].value.str);
	event_add_int(merge_ev1,test_fields[1].key, test_fields[1].value.intmax);
	struct event *merge_ev2 = event_create(merge_ev1);
	event_add_category(merge_ev2, &test_cats[2]);
	event_add_category(merge_ev2, &test_cats[1]);
	event_add_timeval(merge_ev2,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_int(merge_ev2,test_fields[1].key, test_fields[1].value.intmax);
	event_set_name(merge_ev2, "evname");
	e_info(merge_ev2, "info message");
	l = __LINE__ - 1;
	event_unref(&merge_ev1);
	event_unref(&merge_ev2);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	0	1	0	0"
			"	s"__FILE__"	%d	l0	0"
			"	nevname	ctest3	ctest2	ctest1	Tkey3"
			"	10	0	Ikey2	20"
			"	Skey1	str1\n", l));
	test_end();
}

static void test_merge_events2(void)
{
	int l;
	uint64_t id;
	TST_BEGIN("merge events parent sent to stats");
	struct event *parent_ev = event_create(NULL);
	event_add_category(parent_ev, &test_cats[3]);
	parent_ev->sent_to_stats_id = parent_ev->change_id;
	struct event *merge_ev1 = event_create(parent_ev);
	event_add_category(merge_ev1, &test_cats[0]);
	event_add_category(merge_ev1, &test_cats[1]);
	event_add_str(merge_ev1,test_fields[0].key, test_fields[0].value.str);
	event_add_int(merge_ev1,test_fields[1].key, test_fields[1].value.intmax);
	struct event *merge_ev2 = event_create(merge_ev1);
	event_add_category(merge_ev2, &test_cats[2]);
	event_add_category(merge_ev2, &test_cats[1]);
	event_add_timeval(merge_ev2,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_int(merge_ev2,test_fields[1].key, test_fields[1].value.intmax);
	event_set_name(merge_ev2, "evname");
	e_info(merge_ev2, "info message");
	l = __LINE__ - 1;
	id = parent_ev->id;
	event_unref(&parent_ev);
	event_unref(&merge_ev1);
	event_unref(&merge_ev2);
	test_assert(
		compare_test_stats_to(
			"EVENT	0	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d	l0	0"
			"	nevname	ctest3	ctest2	ctest1	Tkey3"
			"	10	0	Ikey2	20"
			"	Skey1	str1\n"
			"END	15\n", id, l));
	test_end();
}

static void test_skip_parents(void)
{
	int l, lp;
	uint64_t id;
	TST_BEGIN("skip empty parents");
	struct event *parent_to_log = event_create(NULL);
	lp = __LINE__ - 1;
	id = parent_to_log->id;
	event_add_category(parent_to_log, &test_cats[0]);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent1 = event_create(parent_to_log);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent2 = event_create(empty_parent1);
	ioloop_timeval.tv_sec++;
	struct event *child_ev = event_create(empty_parent2);
	event_add_category(child_ev, &test_cats[1]);
	event_set_name(child_ev, "evname");
	e_info(child_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_to_log);
	event_unref(&empty_parent1);
	event_unref(&empty_parent2);
	event_unref(&child_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	0	%"PRIu64"	1	3	0	"
			"s"__FILE__"	%d	l3	0	nevname"
			"	ctest2\nEND\t%"PRIu64"\n", id, lp, id, l, id));
	test_end();
}

static void test_merge_events_skip_parents(void)
{
	int lp, l;
	uint64_t id;
	TST_BEGIN("merge events and skip empty parents");
	struct event *parent_to_log = event_create(NULL);
	lp = __LINE__ - 1;
	id = parent_to_log->id;
	event_add_category(parent_to_log, &test_cats[0]);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent1 = event_create(parent_to_log);
	ioloop_timeval.tv_sec++;
	struct event *empty_parent2 = event_create(empty_parent1);
	ioloop_timeval.tv_sec++;
	struct event *child1_ev = event_create(empty_parent2);
	event_add_category(child1_ev, &test_cats[1]);
	event_add_category(child1_ev, &test_cats[2]);
	event_add_int(child1_ev,test_fields[1].key, test_fields[1].value.intmax);
	event_add_str(child1_ev,test_fields[0].key, test_fields[0].value.str);
	struct event *child2_ev = event_create(empty_parent2);
	event_add_category(child2_ev, &test_cats[3]);
	event_add_category(child2_ev, &test_cats[4]);
	event_add_timeval(child2_ev,test_fields[2].key,
			  &test_fields[2].value.timeval);
	event_add_str(child2_ev,test_fields[3].key, test_fields[3].value.str);
	event_set_name(child2_ev, "evname");
	e_info(child2_ev, "info message");
	l = __LINE__ - 1;
	event_unref(&parent_to_log);
	event_unref(&empty_parent1);
	event_unref(&empty_parent2);
	event_unref(&child1_ev);
	event_unref(&child2_ev);
	test_assert(
		compare_test_stats_to(
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1\n"
			"EVENT	0	%"PRIu64"	1	3	0	"
			"s"__FILE__"	%d	l3	0	nevname	"
			"ctest4	ctest5	Tkey3	10	0	Skey4"
			"	str4\nEND\t%"PRIu64"\n", id, lp, id, l, id));
	test_end();
}

static struct event *make_event(struct event *parent,
				struct event_category *cat,
				int *line_r, uint64_t *id_r)
{
	struct event *event;
	int line;

	event = event_create(parent);
	line = __LINE__ -1;

	if (line_r != NULL)
		*line_r = line;
	if (id_r != NULL)
		*id_r = event->id;

	/* something in the test infrastructure assumes that at least one
	   category is always present - make it happy */
	event_add_category(event, cat);

	/* advance the clock to avoid event sending optimizations */
	ioloop_timeval.tv_sec++;

	return event;
}

static void test_parent_update_post_send(void)
{
	struct event *a, *b, *c;
	uint64_t id;
	int line, line_log1, line_log2;

	TST_BEGIN("parent updated after send");

	a = make_event(NULL, &test_cats[0], &line, &id);
	b = make_event(a, &test_cats[1], NULL, NULL);
	c = make_event(b, &test_cats[2], NULL, NULL);

	/* set initial field values */
	event_add_int(a, "a", 1);
	event_add_int(b, "b", 2);
	event_add_int(c, "c", 3);

	/* force 'a' event to be sent */
	event_set_name(b, "evname");
	e_info(b, "field 'a' should be 1");
	line_log1 = __LINE__ - 1;

	event_add_int(a, "a", 1000); /* update parent */

	/* log child, which should re-sent parent */
	event_set_name(c, "evname");
	e_info(c, "field 'a' should be 1000");
	line_log2 = __LINE__ - 1;

	event_unref(&a);
	event_unref(&b);
	event_unref(&c);

	/* EVENT <parent> <type> ... */
	/* BEGIN <id> <parent> <type> ... */
	/* END <id> */
	test_assert(
		compare_test_stats_to(
			/* first e_info() */
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d	ctest1"
			"	Ia	1\n"
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest2" "	Ib	2\n"
			/* second e_info() */
			"UPDATE	%"PRIu64"	0	0	0"
			"	s"__FILE__"	%d	ctest1"
			"	Ia	1000\n"
			"BEGIN	%"PRIu64"	%"PRIu64"	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest2	Ib	2\n"
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest3"
			"	Ic	3\n"
			"END\t%"PRIu64"\n"
			"END\t%"PRIu64"\n",
			id, line, /* BEGIN */
			id, line_log1, /* EVENT */
			id, line, /* UPDATE */
			id + 1, id, line, /* BEGIN */
			id + 1, line_log2, /* EVENT */
			id + 1 /* END */,
			id /* END */));

	test_end();
}

static void test_large_event_id(void)
{
	TST_BEGIN("large event id");
	int line, line_log1, line_log2, line_log3;
	struct event *a, *b;
	uint64_t id;

	a = make_event(NULL, &test_cats[0], &line, &id);
	a->id += 1000000;
	id = a->id;
	a->change_id++;
	b = make_event(a, &test_cats[1], NULL, NULL);

	ioloop_timeval.tv_sec++;
	event_set_name(a, "evname");
	e_info(a, "emit");
	line_log1 = __LINE__-1;
	ioloop_timeval.tv_sec++;
	event_set_name(b, "evname");
	e_info(b, "emit");
	line_log2 = __LINE__-1;
	event_add_int(a, "test1", 1);
	event_set_name(b, "evname");
	e_info(b, "emit");
	line_log3 = __LINE__-1;

	event_unref(&b);
	event_unref(&a);

	test_assert(
		compare_test_stats_to(
			/* first e_info() */
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest1\n"
			"BEGIN	%"PRIu64"	0	1	0	0"
			"	s"__FILE__"	%d"
			"	l0	0	ctest1\n"
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest2\n"
			"UPDATE	%"PRIu64"	0	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	ctest1	Itest1	1\n"
			"EVENT	0	%"PRIu64"	1	1	0"
			"	s"__FILE__"	%d"
			"	l1	0	nevname	ctest2\n"
			"END	%"PRIu64"\n",
			(uint64_t)0, line_log1,
			id, line,
			id, line_log2,
			id, line,
			id, line_log3,
			id
		)
	);

	test_end();
}

static void test_global_event(void)
{
	TST_BEGIN("merge events global");
	struct event *merge_ev1 = event_create(NULL);
	event_add_category(merge_ev1, &test_cats[0]);
	event_add_str(merge_ev1,test_fields[0].key, test_fields[0].value.str);
	struct event *merge_ev2 = event_create(merge_ev1);
	event_add_int(merge_ev2,test_fields[1].key, test_fields[1].value.intmax);

	struct event *global_event = event_create(NULL);
	int global_event_line = __LINE__ - 1;
	uint64_t global_event_id = global_event->id;
	event_add_str(global_event, "global", "value");
	event_push_global(global_event);

	struct timeval tv;
	event_get_create_time(merge_ev1, &tv);

	event_set_name(merge_ev2, "evname");
	e_info(merge_ev2, "info message");
	int log_line = __LINE__ - 1;

	event_pop_global(global_event);
	event_unref(&merge_ev1);
	event_unref(&merge_ev2);
	event_unref(&global_event);

	test_assert(
		compare_test_stats_to(
			"BEGIN\t%"PRIu64"\t0\t1\t0\t0"
			"\ts"__FILE__"\t%d"
			"\tSglobal\tvalue\n"
			"EVENT\t%"PRIu64"\t0\t1\t0\t0"
			"\ts"__FILE__"\t%d\tl0\t0\tnevname"
			"\tctest1\tIkey2\t20\tSkey1\tstr1\n"
			"END\t%"PRIu64"\n",
			global_event_id, global_event_line,
			global_event_id, log_line,
			global_event_id));
	test_end();
}

static int run_tests(void)
{
	int ret;
	void (*const tests[])(void) = {
		test_no_merging1,
		test_no_merging2,
		test_no_merging3,
		test_merge_events1,
		test_merge_events2,
		test_skip_parents,
		test_merge_events_skip_parents,
		test_parent_update_post_send,
		test_large_event_id,
		test_global_event,
		NULL
	};
	stats_buf = str_new(default_pool, 512);
	struct stats_client *stats_client =
		stats_client_init_unittest(stats_buf,
			"category=test1 OR category=test2 OR category=test3 OR "
			"category=test4 OR category=test5");
	register_all_categories();
	str_truncate(stats_buf, 0);

	ret = test_run(tests);
	stats_client_deinit(&stats_client);
	str_free(&stats_buf);
	return ret;
}

int main(void)
{
	int ret;
	i_set_info_handler(test_fail_callback);
	lib_init();
	ret = run_tests();
	lib_deinit();
	return ret;
}
