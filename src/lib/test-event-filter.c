/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "event-filter.h"

static void test_event_filter_override_parent_fields(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: override parent fields");

	struct event *parent = event_create(NULL);
	event_add_str(parent, "str", "parent_str");
	event_add_str(parent, "parent_str", "parent_str");
	event_add_int(parent, "int1", 0);
	event_add_int(parent, "int2", 5);
	event_add_int(parent, "parent_int", 6);

	struct event *child = event_create(parent);
	event_add_str(child, "str", "child_str");
	event_add_str(child, "child_str", "child_str");
	event_add_int(child, "int1", 6);
	event_add_int(child, "int2", 0);
	event_add_int(child, "child_int", 8);

	/* parent matches: test a mix of parent/child fields */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=parent_str AND int1=0 AND int2=5", filter, &error) == 0);
	test_assert(event_filter_match(filter, parent, &failure_ctx));
	test_assert(!event_filter_match(filter, child, &failure_ctx));
	event_filter_unref(&filter);

	/* parent matches: test fields that exist only in parent */
	filter = event_filter_create();
	test_assert(event_filter_parse("parent_str=parent_str AND parent_int=6", filter, &error) == 0);
	test_assert(event_filter_match(filter, parent, &failure_ctx));
	test_assert(event_filter_match(filter, child, &failure_ctx));
	event_filter_unref(&filter);

	/* child matches: test a mix of parent/child fields */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=child_str AND int1=6 AND int2=0", filter, &error) == 0);
	test_assert(event_filter_match(filter, child, &failure_ctx));
	test_assert(!event_filter_match(filter, parent, &failure_ctx));
	event_filter_unref(&filter);

	/* child matches: test fields that exist only in child */
	filter = event_filter_create();
	test_assert(event_filter_parse("child_str=child_str AND child_int=8", filter, &error) == 0);
	test_assert(event_filter_match(filter, child, &failure_ctx));
	test_assert(!event_filter_match(filter, parent, &failure_ctx));
	event_filter_unref(&filter);

	event_unref(&parent);
	event_unref(&child);
	test_end();
}

static void test_event_filter_clear_parent_fields(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};
	const char *keys[] = { "str", "int" };

	test_begin("event filter: clear parent fields");

	struct event *parent = event_create(NULL);
	event_add_str(parent, "str", "parent_str");
	event_add_int(parent, "int", 0);

	struct event *child = event_create(parent);
	event_field_clear(child, "str");
	event_field_clear(child, "int");

	for (unsigned int i = 0; i < N_ELEMENTS(keys); i++) {
		/* match any value */
		const char *query = t_strdup_printf("%s=*", keys[i]);
		filter = event_filter_create();
		test_assert(event_filter_parse(query, filter, &error) == 0);

		test_assert_idx(event_filter_match(filter, parent, &failure_ctx), i);
		test_assert_idx(!event_filter_match(filter, child, &failure_ctx), i);
		event_filter_unref(&filter);
	}

	/* match empty field */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=\"\"", filter, &error) == 0);
	test_assert(!event_filter_match(filter, parent, &failure_ctx));
	test_assert(event_filter_match(filter, child, &failure_ctx));
	event_filter_unref(&filter);

	/* match nonexistent field */
	filter = event_filter_create();
	test_assert(event_filter_parse("nonexistent=\"\"", filter, &error) == 0);
	test_assert(event_filter_match(filter, parent, &failure_ctx));
	test_assert(event_filter_match(filter, child, &failure_ctx));
	event_filter_unref(&filter);

	event_unref(&parent);
	event_unref(&child);
	test_end();
}

static void test_event_filter_inc_int(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: create and update keys with event_inc_int");

	struct event *root = event_create(NULL);

	filter = event_filter_create();
	test_assert(event_filter_parse("int=14", filter, &error) == 0);

	const struct event_field *f = event_find_field_recursive(root, "int");
	i_assert(f == NULL);
	test_assert(!event_filter_match(filter, root, &failure_ctx));

	event_inc_int(root, "int", 7);
	test_assert(!event_filter_match(filter, root, &failure_ctx));
	f = event_find_field_recursive(root, "int");
	i_assert(f != NULL);
	test_assert_strcmp(f->key, "int");
	test_assert(f->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX);
	test_assert(f->value.intmax == 7);

	event_inc_int(root, "int", 7);
	test_assert(event_filter_match(filter, root, &failure_ctx));
	f = event_find_field_recursive(root, "int");
	i_assert(f != NULL);
	test_assert_strcmp(f->key, "int");
	test_assert(f->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX);
	test_assert(f->value.intmax == 14);

	event_filter_unref(&filter);
	event_unref(&root);
	test_end();
}

static void test_event_filter_parent_category_match(void)
{
	static struct event_category parent_category = {
		.name = "parent",
	};
	static struct event_category child_category = {
		.parent = &parent_category,
		.name = "child",
	};
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: parent category match");

	struct event *e = event_create(NULL);
	event_add_category(e, &child_category);

	filter = event_filter_create();
	test_assert(event_filter_parse("category=parent", filter, &error) == 0);

	test_assert(event_filter_match(filter, e, &failure_ctx));

	event_filter_unref(&filter);
	event_unref(&e);
	test_end();
}

void test_event_filter(void)
{
	test_event_filter_override_parent_fields();
	test_event_filter_clear_parent_fields();
	test_event_filter_inc_int();
	test_event_filter_parent_category_match();
}
