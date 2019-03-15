/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "lib-event-private.h"
#include "failures-private.h"

#define CHECK_FLATTEN_SAME(e) \
	check_event_same(event_flatten(e), (e))

#define CHECK_FLATTEN_DIFF(e, c, nc, f, nf) \
	check_event_diff(event_flatten(e), (e), \
			 (c), (nc), \
			 (f), (nf))

static struct event_category cats[] = {
	{ .name = "cat0", },
	{ .name = "cat1", },
};

static void check_event_diff_cats(struct event_category *const *got,
				  unsigned int ngot, const char **exp,
				  unsigned int nexp)
{
	unsigned int i;

	test_assert(ngot == nexp);

	for (i = 0; i < nexp; i++)
		test_assert(strcmp(got[i]->name, exp[i]) == 0);
}

static void check_event_diff_fields(const struct event_field *got, unsigned int ngot,
				    const struct event_field *exp, unsigned int nexp)
{
	unsigned int i;

	test_assert(ngot == nexp);

	for (i = 0; i < nexp; i++) {
		if (got[i].value_type != exp[i].value_type) {
			test_assert(FALSE);
			continue;
		}

		switch (exp[i].value_type) {
		case EVENT_FIELD_VALUE_TYPE_STR:
			test_assert(strcmp(exp[i].value.str,
					   got[i].value.str) == 0);
			break;
		case EVENT_FIELD_VALUE_TYPE_INTMAX:
			test_assert(exp[i].value.intmax == got[i].value.intmax);
			break;
		case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
			test_assert(timeval_cmp(&exp[i].value.timeval,
						&got[i].value.timeval) == 0);
			break;
		}
	}
}

static void check_event_diff(struct event *e, struct event *orig,
			     const char **expected_cats,
			     unsigned int num_expected_cats,
			     const struct event_field *expected_fields,
			     unsigned int num_expected_fields)
{
	struct event_category *const *cats;
	const struct event_field *fields;
	unsigned int num_cats;
	unsigned int num_fields;

	test_assert(e != orig);
	test_assert(e->parent == NULL);

	/* different pointers implies different ids */
	test_assert(e->id != orig->id); /* TODO: does this make sense? */

	test_assert(timeval_cmp(&e->tv_created_ioloop, &orig->tv_created_ioloop) == 0);
	test_assert(timeval_cmp(&e->tv_created, &orig->tv_created) == 0);
	test_assert(timeval_cmp(&e->tv_last_sent, &orig->tv_last_sent) == 0);

	test_assert(strcmp(e->source_filename, orig->source_filename) == 0);
	test_assert(e->source_linenum == orig->source_linenum);

	/* FIXME: check sending name? */

	cats = event_get_categories(e, &num_cats);
	check_event_diff_cats(cats, num_cats,
			      expected_cats, num_expected_cats);

	fields = event_get_fields(e, &num_fields);
	check_event_diff_fields(fields, num_fields,
				expected_fields, num_expected_fields);

	event_unref(&e);
}

static void check_event_same(struct event *e, struct event *orig)
{
	test_assert(e == orig);

	/* the pointers are the same; nothing can possibly differ */

	event_unref(&e);
}

static void test_event_flatten_no_parent(void)
{
	struct event *e;

	test_begin("event flatten: no parent");

	e = event_create(NULL);

	CHECK_FLATTEN_SAME(e);

	event_add_int(e, "abc", 4);
	CHECK_FLATTEN_SAME(e);

	event_add_int(e, "def", 2);
	CHECK_FLATTEN_SAME(e);

	event_add_str(e, "abc", "foo");
	CHECK_FLATTEN_SAME(e);

	event_add_category(e, &cats[0]);
	CHECK_FLATTEN_SAME(e);

	event_unref(&e);

	test_end();
}

static void test_event_flatten_one_parent(void)
{
	static const char *exp_1cat[] = {
		"cat0",
	};
	static const char *exp_2cat[] = {
		"cat1",
		"cat0",
	};
	static struct event_field exp_int = {
		.key = "abc",
		.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
		.value.intmax = 42,
	};
	static struct event_field exp_2int[2] = {
		{
			.key = "abc",
			.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
			.value.intmax = 42,
		},
		{
			.key = "def",
			.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
			.value.intmax = 49,
		},
	};
	static struct event_field exp_1str1int[2] = {
		{
			.key = "abc",
			.value_type = EVENT_FIELD_VALUE_TYPE_STR,
			.value.str = "foo",
		},
		{
			.key = "def",
			.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
			.value.intmax = 49,
		},
	};
	struct event *parent;
	struct event *e;

	test_begin("event flatten: one parent");

	parent = event_create(NULL);

	e = event_create(parent);

	CHECK_FLATTEN_DIFF(e, NULL, 0, NULL, 0);

	event_add_int(e, "abc", 42);
	CHECK_FLATTEN_DIFF(e, NULL, 0, &exp_int, 1);

	event_add_int(e, "def", 49);
	CHECK_FLATTEN_DIFF(e, NULL, 0, exp_2int, 2);

	event_add_str(e, "abc", "foo");
	CHECK_FLATTEN_DIFF(e, NULL, 0, exp_1str1int, 2);

	event_add_category(e, &cats[0]);
	CHECK_FLATTEN_DIFF(e, exp_1cat, 1, exp_1str1int, 2);

	event_add_category(e, &cats[1]);
	CHECK_FLATTEN_DIFF(e, exp_2cat, 2, exp_1str1int, 2);

	event_unref(&e);
	event_unref(&parent);

	test_end();
}

static void test_event_flatten_override_parent_field(void)
{
	static struct event_field exp_int = {
		.key = "abc",
		.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX,
		.value.intmax = 42,
	};
	static struct event_field exp_str = {
		.key = "abc",
		.value_type = EVENT_FIELD_VALUE_TYPE_STR,
		.value.str = "def",
	};
	static struct event_field exp_2str[2] = {
		{
			.key = "abc",
			.value_type = EVENT_FIELD_VALUE_TYPE_STR,
			.value.str = "def",
		},
		{
			.key = "foo",
			.value_type = EVENT_FIELD_VALUE_TYPE_STR,
			.value.str = "bar",
		},
	};
	struct event *parent;
	struct event *e;

	test_begin("event flatten: override parent field");

	parent = event_create(NULL);

	event_add_int(parent, "abc", 5);

	e = event_create(parent);

	event_add_int(e, "abc", 42);

	CHECK_FLATTEN_DIFF(e, NULL, 0, &exp_int, 1);

	event_add_str(e, "abc", "def");
	CHECK_FLATTEN_DIFF(e, NULL, 0, &exp_str, 1);

	event_add_str(parent, "foo", "bar");
	CHECK_FLATTEN_DIFF(e, NULL, 0, exp_2str, 2);

	event_unref(&e);
	event_unref(&parent);

	test_end();
}

void test_event_flatten(void)
{
	test_event_flatten_no_parent();
	test_event_flatten_one_parent();
	test_event_flatten_override_parent_field();
}
