/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "event-filter-private.h"

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

static void test_event_filter_override_global_fields(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: override global fields");

	struct event *global = event_create(NULL);
	event_add_str(global, "str", "global_str");
	event_add_str(global, "global_str", "global_str");
	event_add_int(global, "int1", 0);
	event_add_int(global, "int2", 5);
	event_add_int(global, "global_int", 6);
	event_push_global(global);

	struct event *local = event_create(NULL);
	event_add_str(local, "str", "local_str");
	event_add_str(local, "local_str", "local_str");
	event_add_int(local, "int1", 6);
	event_add_int(local, "int2", 0);
	event_add_int(local, "local_int", 8);

	/* global matches: test a mix of global/local fields */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=global_str AND int1=0 AND int2=5", filter, &error) == 0);
	test_assert(event_filter_match(filter, global, &failure_ctx));
	test_assert(!event_filter_match(filter, local, &failure_ctx));
	event_filter_unref(&filter);

	/* global matches: test fields that exist only in global */
	filter = event_filter_create();
	test_assert(event_filter_parse("global_str=global_str AND global_int=6", filter, &error) == 0);
	test_assert(event_filter_match(filter, global, &failure_ctx));
	test_assert(event_filter_match(filter, local, &failure_ctx));
	event_filter_unref(&filter);

	/* local matches: test a mix of global/local fields */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=local_str AND int1=6 AND int2=0", filter, &error) == 0);
	test_assert(event_filter_match(filter, local, &failure_ctx));
	test_assert(!event_filter_match(filter, global, &failure_ctx));
	event_filter_unref(&filter);

	/* local matches: test fields that exist only in local */
	filter = event_filter_create();
	test_assert(event_filter_parse("local_str=local_str AND local_int=8", filter, &error) == 0);
	test_assert(event_filter_match(filter, local, &failure_ctx));
	test_assert(!event_filter_match(filter, global, &failure_ctx));
	event_filter_unref(&filter);

	event_pop_global(global);
	event_unref(&global);
	event_unref(&local);
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

static void test_event_filter_clear_global_fields(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};
	const char *keys[] = { "str", "int" };

	test_begin("event filter: clear global fields");

	struct event *global = event_create(NULL);
	event_add_str(global, "str", "global_str");
	event_add_int(global, "int", 0);
	event_push_global(global);

	struct event *local = event_create(NULL);
	event_field_clear(local, "str");
	event_field_clear(local, "int");

	for (unsigned int i = 0; i < N_ELEMENTS(keys); i++) {
		/* match any value */
		const char *query = t_strdup_printf("%s=*", keys[i]);
		filter = event_filter_create();
		test_assert(event_filter_parse(query, filter, &error) == 0);

		test_assert_idx(event_filter_match(filter, global, &failure_ctx), i);
		test_assert_idx(!event_filter_match(filter, local, &failure_ctx), i);
		event_filter_unref(&filter);
	}

	/* match empty field */
	filter = event_filter_create();
	test_assert(event_filter_parse("str=\"\"", filter, &error) == 0);
	test_assert(!event_filter_match(filter, global, &failure_ctx));
	test_assert(event_filter_match(filter, local, &failure_ctx));
	event_filter_unref(&filter);

	/* match nonexistent field */
	filter = event_filter_create();
	test_assert(event_filter_parse("nonexistent=\"\"", filter, &error) == 0);
	test_assert(event_filter_match(filter, global, &failure_ctx));
	test_assert(event_filter_match(filter, local, &failure_ctx));
	event_filter_unref(&filter);

	event_pop_global(global);
	event_unref(&global);
	event_unref(&local);
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

static void test_event_filter_strlist(void)
{
	struct event_filter *filter;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: match string list");

	struct event *e = event_create(NULL);

	filter = event_filter_create();
	/* should match empty list */
	event_filter_parse("abc=\"\"", filter, NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* should still be empty */
	event_strlist_append(e, "abc", NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));

	/* should not match non-empty list */
	event_strlist_append(e, "abc", "one");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* should match non-empty list that has value 'one' */
	filter = event_filter_create();
	event_strlist_append(e, "abc", "two");
	event_filter_parse("abc=one", filter, NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* should match non-empty list that has no value 'three' */
	filter = event_filter_create();
	event_filter_parse("abc=one AND NOT abc=three", filter, NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	event_filter_parse("abc>one", filter, NULL);
	test_expect_error_string("Event filter for string list field 'abc' only "
				 "supports equality operation '=' not '>'.");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	event_unref(&e);
	test_end();
}

static void test_event_filter_strlist_recursive(void)
{
	struct event_filter *filter;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: match string list - recursive");

	struct event *parent = event_create(NULL);
	struct event *e = event_create(parent);

	/* empty filter: parent is non-empty */
	filter = event_filter_create();
	event_filter_parse("list1=\"\"", filter, NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_strlist_append(parent, "list1", "foo");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* matching filter: matches parent */
	filter = event_filter_create();
	event_filter_parse("list2=parent", filter, NULL);
	/* empty: */
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* set parent but no child: */
	event_strlist_append(parent, "list2", "parent");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* set child to non-matching: */
	event_strlist_append(e, "list2", "child");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* matching filter: matches child */
	filter = event_filter_create();
	event_filter_parse("list3=child", filter, NULL);
	/* empty: */
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* set child but no parent: */
	event_strlist_append(e, "list3", "child");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* set parent to non-matching: */
	event_strlist_append(e, "list3", "parent");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	event_unref(&e);
	event_unref(&parent);
	test_end();
}

static void test_event_filter_strlist_global_events(void)
{
	struct event_filter *filter;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: match string list - global events");

	struct event *global = event_create(NULL);
	event_push_global(global);

	struct event *e = event_create(NULL);

	/* empty filter: global is non-empty */
	filter = event_filter_create();
	event_filter_parse("list1=\"\"", filter, NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_strlist_append(global, "list1", "foo");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* matching filter: matches global */
	filter = event_filter_create();
	event_filter_parse("list2=global", filter, NULL);
	/* empty: */
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* set global but no local: */
	event_strlist_append(global, "list2", "global");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* set local to non-matching: */
	event_strlist_append(e, "list2", "local");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	/* matching filter: matches local */
	filter = event_filter_create();
	event_filter_parse("list3=local", filter, NULL);
	/* empty: */
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* set local but no global: */
	event_strlist_append(e, "list3", "local");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* set global to non-matching: */
	event_strlist_append(e, "list3", "global");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	event_unref(&e);
	event_pop_global(global);
	event_unref(&global);
	test_end();
}

static void test_event_filter_named_and_str(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event name and str");

	filter = event_filter_create();
	struct event *e_noname_nostr = event_create(NULL);
	struct event *e_noname_str = event_create(NULL);
	event_add_str(e_noname_str, "str", "str");
	struct event *e_noname_wrongstr = event_create(NULL);
	event_add_str(e_noname_wrongstr, "str", "wrong");
	struct event *e_named_nostr = event_create(NULL);
	event_set_name(e_named_nostr, "named");
	struct event *e_named_str = event_create(NULL);
	event_set_name(e_named_str, "named");
	event_add_str(e_named_str, "str", "str");
	struct event *e_named_wrongstr = event_create(NULL);
	event_set_name(e_named_wrongstr, "named");
	event_add_str(e_named_wrongstr, "str", "wrong");
	struct event *e_wrongname_nostr = event_create(NULL);
	event_set_name(e_wrongname_nostr, "wrong");
	struct event *e_wrongname_str = event_create(NULL);
	event_set_name(e_wrongname_str, "wrong");
	event_add_str(e_wrongname_str, "str", "str");
	struct event *e_wrongname_wrongstr = event_create(NULL);
	event_set_name(e_wrongname_wrongstr, "wrong");
	event_add_str(e_wrongname_wrongstr, "str", "wrong");

	test_assert(event_filter_parse("event=named AND str=str", filter, &error) == 0);
	test_assert(filter->named_queries_only);
	test_assert(!event_filter_match(filter, e_noname_nostr, &failure_ctx));
	test_assert(!event_filter_match(filter, e_noname_str, &failure_ctx));
	test_assert(!event_filter_match(filter, e_noname_wrongstr, &failure_ctx));
	test_assert(!event_filter_match(filter, e_named_nostr, &failure_ctx));
	test_assert(event_filter_match(filter, e_named_str, &failure_ctx));
	test_assert(!event_filter_match(filter, e_named_wrongstr, &failure_ctx));
	test_assert(!event_filter_match(filter, e_wrongname_nostr, &failure_ctx));
	test_assert(!event_filter_match(filter, e_wrongname_str, &failure_ctx));
	test_assert(!event_filter_match(filter, e_wrongname_wrongstr, &failure_ctx));

	event_filter_unref(&filter);
	event_unref(&e_noname_nostr);
	event_unref(&e_noname_str);
	event_unref(&e_noname_wrongstr);
	event_unref(&e_named_nostr);
	event_unref(&e_named_str);
	event_unref(&e_named_wrongstr);
	event_unref(&e_wrongname_nostr);
	event_unref(&e_wrongname_str);
	event_unref(&e_wrongname_wrongstr);
	test_end();
}

static void test_event_filter_named_or_str(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event name or str");

	filter = event_filter_create();
	struct event *e_noname_nostr = event_create(NULL);
	struct event *e_noname_str = event_create(NULL);
	event_add_str(e_noname_str, "str", "str");
	struct event *e_noname_wrongstr = event_create(NULL);
	event_add_str(e_noname_wrongstr, "str", "wrong");
	struct event *e_named_nostr = event_create(NULL);
	event_set_name(e_named_nostr, "named");
	struct event *e_named_str = event_create(NULL);
	event_set_name(e_named_str, "named");
	event_add_str(e_named_str, "str", "str");
	struct event *e_named_wrongstr = event_create(NULL);
	event_set_name(e_named_wrongstr, "named");
	event_add_str(e_named_wrongstr, "str", "wrong");
	struct event *e_wrongname_nostr = event_create(NULL);
	event_set_name(e_wrongname_nostr, "wrong");
	struct event *e_wrongname_str = event_create(NULL);
	event_set_name(e_wrongname_str, "wrong");
	event_add_str(e_wrongname_str, "str", "str");
	struct event *e_wrongname_wrongstr = event_create(NULL);
	event_set_name(e_wrongname_wrongstr, "wrong");
	event_add_str(e_wrongname_wrongstr, "str", "wrong");

	test_assert(event_filter_parse("event=named OR str=str", filter, &error) == 0);
	test_assert(!filter->named_queries_only);

	test_assert(!event_filter_match(filter, e_noname_nostr, &failure_ctx));
	test_assert(event_filter_match(filter, e_noname_str, &failure_ctx));
	test_assert(!event_filter_match(filter, e_noname_wrongstr, &failure_ctx));
	test_assert(event_filter_match(filter, e_named_nostr, &failure_ctx));
	test_assert(event_filter_match(filter, e_named_str, &failure_ctx));
	test_assert(event_filter_match(filter, e_named_wrongstr, &failure_ctx));
	test_assert(!event_filter_match(filter, e_wrongname_nostr, &failure_ctx));
	test_assert(event_filter_match(filter, e_wrongname_str, &failure_ctx));
	test_assert(!event_filter_match(filter, e_wrongname_wrongstr, &failure_ctx));

	event_filter_unref(&filter);
	event_unref(&e_noname_nostr);
	event_unref(&e_noname_str);
	event_unref(&e_noname_wrongstr);
	event_unref(&e_named_nostr);
	event_unref(&e_named_str);
	event_unref(&e_named_wrongstr);
	event_unref(&e_wrongname_nostr);
	event_unref(&e_wrongname_str);
	event_unref(&e_wrongname_wrongstr);
	test_end();
}

static void test_event_filter_named_separate_from_str(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event name separate from str");

	filter = event_filter_create();
	struct event *e_named = event_create(NULL);
	event_set_name(e_named, "named");
	struct event *e_noname = event_create(NULL);
	event_add_str(e_noname, "str", "str");

	test_assert(event_filter_parse("event=named", filter, &error) == 0);
	test_assert(event_filter_parse("str=str", filter, &error) == 0);
	test_assert(!filter->named_queries_only);
	test_assert(event_filter_match(filter, e_named, &failure_ctx));
	test_assert(event_filter_match(filter, e_noname, &failure_ctx));

	event_filter_unref(&filter);
	event_unref(&e_named);
	event_unref(&e_noname);
	test_end();
}

static void test_event_filter_duration(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event duration");

	/* we check that we can actually match duration field */
	filter = event_filter_create();
	test_assert(event_filter_parse("duration < 1000", filter, &error) == 0);

	struct event *e = event_create(NULL);
	test_assert(event_filter_match(filter, e, &failure_ctx));

	event_filter_unref(&filter);
	event_unref(&e);
	test_end();
}

static void test_event_filter_numbers(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event numeric matching");

	/* we check that we can actually match duration field */
	filter = event_filter_create();
	test_assert(event_filter_parse("number > 0", filter, &error) == 0);

	struct event *e = event_create(NULL);
	event_add_int(e, "number", 1);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_add_int(e, "number", 0);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_add_int(e, "number", -1);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("number < 0", filter, &error) == 0);
	event_add_int(e, "number", 1);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_add_int(e, "number", 0);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	event_add_int(e, "number", -1);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	event_add_int(e, "number", 0);

	filter = event_filter_create();
	test_assert(event_filter_parse("number=0", filter, &error) == 0);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("number=*", filter, &error) == 0);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("number > fish", filter, &error) == 0);
	test_expect_error_string("Event filter matches integer field 'number' "
				 "against non-integer value 'fish'");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("number=fish", filter, &error) == 0);
	test_expect_error_string("Event filter matches integer field 'number' "
				 "against non-integer value 'fish'");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	event_add_int(e, "status_code", 204);

	filter = event_filter_create();
	test_assert(event_filter_parse("status_code > 2*", filter, &error) == 0);
	test_expect_error_string("Event filter matches integer field "
				 "'status_code' against wildcard value '2*' "
				 "with an incompatible operation '>', please "
				 "use '='.");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("status_code = 2*", filter, &error) == 0);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	event_unref(&e);
	test_end();
}

static struct ip_addr test_addr2ip(const char *addr)
{
	struct ip_addr ip;
	if (net_addr2ip(addr, &ip) < 0)
		i_unreached();
	return ip;
}

static void test_event_filter_ips(void)
{
	struct event_filter *filter;
	const char *error;
	struct ip_addr ip;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: event ip matching");

	filter = event_filter_create();
	test_assert(event_filter_parse("ip = 127.0.0.1", filter, &error) == 0);

	struct event *e = event_create(NULL);
	/* ip match */
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* ip mismatch */
	test_assert(net_addr2ip("127.0.0.2", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* string ip match */
	event_add_str(e, "ip", "127.0.0.1");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* numeric ip mismatch */
	event_add_int(e, "ip", 2130706433);
	test_expect_error_string("Event filter matches integer field 'ip' "
				 "against non-integer value '127.0.0.1'");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("ip = 127.0.0.*", filter, &error) == 0);
	/* wildcard match */
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* wildcard mismatch */
	test_assert(net_addr2ip("127.0.1.1", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* wildcard match as string */
	event_add_str(e, "ip", "127.0.0.3");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("ip = 127.0.0.0/16", filter, &error) == 0);
	/* network mask match */
	test_assert(net_addr2ip("127.0.255.255", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(event_filter_match(filter, e, &failure_ctx));
	/* network mask mismatch */
	test_assert(net_addr2ip("127.1.255.255", &ip) == 0);
	event_add_ip(e, "ip", &ip);
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* network mask mismatch as string */
	event_add_str(e, "ip", "127.0.123.45");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	/* network mask match as string */
	event_add_str(e, "ip", "127.0.0.0/16");
	test_assert(event_filter_match(filter, e, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	test_assert(event_filter_parse("ip = fish", filter, &error) == 0);
	event_add_ip(e, "ip", &ip);
	test_expect_error_string("Event filter matches IP field 'ip' "
				 "against non-IP value 'fish'");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	const struct {
		const char *filter;
		struct ip_addr ip;
		bool match;
	} tests[] = {
		{ "ip = ::1", test_addr2ip("::1"), TRUE },
		{ "ip = ::2", test_addr2ip("::1"), FALSE },

		{ "ip = ::1/128", test_addr2ip("::1"), TRUE },
		{ "ip = ::1/126", test_addr2ip("::2"), TRUE },
		{ "ip = \"::1/126\"", test_addr2ip("::3"), TRUE },
		{ "ip = ::1/126", test_addr2ip("::4"), FALSE },

		{ "ip = 2001::/8", test_addr2ip("2001::1"), TRUE },
		{ "ip = 2001::/8", test_addr2ip("20ff:ffff::1"), TRUE },
		{ "ip = 2001::/8", test_addr2ip("2100::1"), FALSE },

		{ "ip = 2001::1", test_addr2ip("2001::1"), TRUE },
		{ "ip = \"2001::1\"", test_addr2ip("2001::1"), TRUE },
		{ "ip = 2001:0:0:0:0:0:0:1", test_addr2ip("2001::1"), TRUE },
		{ "ip = 2001::1", test_addr2ip("2001::2"), FALSE },

		{ "ip = 2000:1190:c02a:130:a87a:ad7:5b76:3310",
		  test_addr2ip("2000:1190:c02a:130:a87a:ad7:5b76:3310"), TRUE },
		{ "ip = 2001:1190:c02a:130:a87a:ad7:5b76:3310",
		  test_addr2ip("2000:1190:c02a:130:a87a:ad7:5b76:3310"), FALSE },

		{ "ip = fe80::1%lo", test_addr2ip("fe80::1%lo"), TRUE },
	};
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		filter = event_filter_create();
		test_assert_idx(event_filter_parse(tests[i].filter, filter, &error) == 0, i);
		event_add_ip(e, "ip", &tests[i].ip);
		test_assert_idx(event_filter_match(filter, e, &failure_ctx) == tests[i].match, i);
		event_filter_unref(&filter);
	}

	event_unref(&e);
	test_end();
}

static void test_event_filter_size_values(void)
{
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	test_begin("event filter: sizes with different size units");

	const struct {
		const char *filter;
		intmax_t value;
		bool match;
	} test_cases[] = {
		/* Make sure negative values do not interfere with the
		   existing event filtering. */
		{ "field = -1", -1, TRUE },

		{ "field = 1", 1, TRUE },
		{ "field = 1b", 1, TRUE },
		{ "field = 1B", 1, TRUE },
		{ "field < 1B", 1, FALSE },
		{ "field > 1B", 1, FALSE },

		{ "field = 1k", 1024, TRUE },
		{ "field = 1KB", 1024, TRUE },
		{ "field = 1Kb", 1024, TRUE },
		{ "field = 1kB", 1024, TRUE },
		{ "field = 1kb", 1024, TRUE },
		{ "field = 1KIB", 1024, TRUE },
		{ "field = 1KiB", 1024, TRUE },
		{ "field >= 1KB", 1024, TRUE },
		{ "field <= 1KB", 1024, TRUE },
		{ "field > 1B", 1024, TRUE },
		{ "field > 1000", 1024, TRUE },
		{ "field < 1KB", 1024, FALSE },
		{ "field > 1KB", 1024, FALSE },

		{ "field = 1MB", 1024 * 1024, TRUE },
		{ "field >= 1MB", 1024 * 1024, TRUE },
		{ "field <= 1MB", 1024 * 1024, TRUE },
		{ "field > 1KB", 1024 * 1024, TRUE },
		{ "field > 1000000", 1024 * 1024, TRUE },
		{ "field < 1MB", 1024 * 1024, FALSE },
		{ "field > 1MB", 1024 * 1024, FALSE },

		{ "field = 1g", 1024 * 1024 * 1024, TRUE },
		{ "field = 1GB", 1024 * 1024 * 1024, TRUE },
		{ "field >= 1GB", 1024 * 1024 * 1024, TRUE },
		{ "field <= 1GB", 1024 * 1024 * 1024, TRUE },
		{ "field < 1TB", 1024 * 1024 * 1024, TRUE },
		{ "field > 1000000000", 1024 * 1024 * 1024, TRUE },
		{ "field < 1GB", 1024 * 1024 * 1024, FALSE },
		{ "field > 1GB", 1024 * 1024 * 1024, FALSE },

		{ "field = 1t", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field = 1TB", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field >= 1TB", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field <= 1TB", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field > 1GB", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field > 1000000000000", 1024ULL * 1024 * 1024 * 1024, TRUE },
		{ "field < 1TB", 1024ULL * 1024 * 1024 * 1024, FALSE },
		{ "field > 1TB", 1024ULL * 1024 * 1024 * 1024, FALSE },
	};

	struct event_filter *filter;
	struct event *e;

	for (unsigned int i = 0; i < N_ELEMENTS(test_cases); i++) {
		e = event_create(NULL);
		filter = event_filter_create();

		event_add_int(e, "field", test_cases[i].value);
		test_assert_idx(event_filter_parse(test_cases[i].filter, filter,
						   &error) == 0, i);
		bool result = event_filter_match(filter, e, &failure_ctx);
		test_assert_idx(result == test_cases[i].match, i);

		event_filter_unref(&filter);
		event_unref(&e);
	}

	test_end();
}

static void test_event_filter_interval_values(void)
{
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	test_begin("event filter: sizes with different interval units");

	const struct {
		const char *filter;
		intmax_t value;
		bool match;
	} test_cases[] = {
		/* Make sure negative values do not interfere with the
		   existing event filtering. */
		{ "field = -1", -1, TRUE },

		{ "field = 1milliseconds", 1000, TRUE },
		{ "field = 1millisecs", 1000, TRUE },
		{ "field = 1mseconds", 1000, TRUE },
		{ "field = 1msecs", 1000, TRUE },
		{ "field = 1ms", 1000, TRUE },
		{ "field = 1000", 1000, TRUE },
		{ "field >= 1msecs", 1000, TRUE },
		{ "field <= 1msecs", 1000, TRUE },
		{ "field > 1", 1000, TRUE },
		{ "field > 1msecs", 1000, FALSE },
		{ "field < 1msecs", 1000, FALSE },

		{ "field = 1seconds", 1000 * 1000, TRUE },
		{ "field = 1secs", 1000 * 1000, TRUE },
		{ "field = 1s", 1000 * 1000, TRUE },
		{ "field = 1000000", 1000 * 1000, TRUE },
		{ "field >= 1secs", 1000 * 1000, TRUE },
		{ "field <= 1secs", 1000 * 1000, TRUE },
		{ "field > 1msecs", 1000 * 1000, TRUE },
		{ "field > 1secs", 1000 * 1000, FALSE },
		{ "field < 1secs", 1000 * 1000, FALSE },

		{ "field = 1minutes", 60 * 1000 * 1000, TRUE },
		{ "field = 1mins", 60 * 1000 * 1000, TRUE },
		{ "field = 60000000", 60 * 1000 * 1000, TRUE },
		{ "field >= 1mins", 60 * 1000 * 1000, TRUE },
		{ "field <= 1mins", 60 * 1000 * 1000, TRUE },
		{ "field > 1secs", 60 * 1000 * 1000, TRUE },
		{ "field > 1mins", 60 * 1000 * 1000, FALSE },
		{ "field < 1mins", 60 * 1000 * 1000, FALSE },

		{ "field = 1hours", 60L * 60 * 1000 * 1000, TRUE },
		{ "field = 1h", 60L * 60 * 1000 * 1000, TRUE },
		{ "field = 3600000000", 60L * 60 * 1000 * 1000, TRUE },
		{ "field >= 1hours", 60L * 60 * 1000 * 1000, TRUE },
		{ "field <= 1hours", 60L * 60 * 1000 * 1000, TRUE },
		{ "field > 1mins", 60L * 60 * 1000 * 1000, TRUE },
		{ "field > 1hours", 60L * 60 * 1000 * 1000, FALSE },
		{ "field < 1hours", 60L * 60 * 1000 * 1000, FALSE },

		{ "field = 1days", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field = 1d", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field = 86400000000", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field >= 1days", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field <= 1days", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field > 1hours", 24L * 60 * 60 * 1000 * 1000, TRUE },
		{ "field > 1days", 24L * 60 * 60 * 1000 * 1000, FALSE },
		{ "field < 1days", 24L * 60 * 60 * 1000 * 1000, FALSE },

		{ "field = 1weeks", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field = 1w", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field = 604800000000", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field >= 1weeks", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field <= 1weeks", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field > 1days", 7L * 24 * 60 * 60 * 1000 * 1000, TRUE },
		{ "field > 1weeks", 7L * 24 * 60 * 60 * 1000 * 1000, FALSE },
		{ "field < 1weeks", 7L * 24 * 60 * 60 * 1000 * 1000, FALSE },
	};

	struct event_filter *filter;
	struct event *e;

	for (unsigned int i = 0; i < N_ELEMENTS(test_cases); i++) {
		e = event_create(NULL);
		filter = event_filter_create();

		event_add_int(e, "field", test_cases[i].value);
		test_assert_idx(event_filter_parse(test_cases[i].filter, filter,
						   &error) == 0, i);
		bool result = event_filter_match(filter, e, &failure_ctx);
		test_assert_idx(result == test_cases[i].match, i);

		event_filter_unref(&filter);
		event_unref(&e);
	}

	test_end();
}

static void test_event_filter_ambiguous_units(void)
{
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	test_begin("event filter: ambiguous units");

	struct event_filter *filter = event_filter_create();

	/* Make sure an ambiguous unit creates a warning. */
	struct event *e_int = event_create(NULL);
	event_add_int(e_int, "field", 1000);
	test_assert(event_filter_parse("field = 1m", filter, &error) == 0);
	test_expect_error_string("Event filter matches integer field 'field' "
				 "with value that has an ambiguous unit '1m'. "
				 "Please use either 'mins' or 'MB' to specify "
				 "interval or size respectively.");
	test_assert(!event_filter_match(filter, e_int, &failure_ctx));
	test_expect_no_more_errors();
	event_unref(&e_int);

	/* String values should not be considered for ambiguous units. */
	struct event *e_str = event_create(NULL);
	event_add_str(e_str, "field", "1m");
	test_assert(event_filter_parse("field = 1m", filter, &error) == 0);
	test_assert(event_filter_match(filter, e_str, &failure_ctx));
	event_unref(&e_str);

	event_filter_unref(&filter);
	test_end();
}

static void test_event_filter_timeval_values(void)
{
	struct event_filter *filter;
	const char *error;
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	test_begin("event filter: timeval filters");

	struct event *e = event_create(NULL);

	struct timeval tv = (struct timeval){ .tv_sec = 0, .tv_usec = 0 };
	event_add_timeval(e, "last_run_time", &tv);

	filter = event_filter_create();
	test_assert(event_filter_parse("last_run_time = 0", filter, &error) == 0);
	test_expect_error_string("Event filter for timeval field "
				 "'last_run_time' is currently not implemented.");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	tv = (struct timeval){ .tv_sec = 1, .tv_usec = 1 };
	event_add_timeval(e, "last_run_time", &tv);

	filter = event_filter_create();
	test_assert(event_filter_parse("last_run_time > 1000000", filter, &error) == 0);
	test_expect_error_string("Event filter for timeval field "
				 "'last_run_time' is currently not implemented.");
	test_assert(!event_filter_match(filter, e, &failure_ctx));
	test_expect_no_more_errors();
	event_filter_unref(&filter);

	event_unref(&e);
	test_end();
}

void test_event_filter(void)
{
	test_event_filter_override_parent_fields();
	test_event_filter_override_global_fields();
	test_event_filter_clear_parent_fields();
	test_event_filter_clear_global_fields();
	test_event_filter_inc_int();
	test_event_filter_parent_category_match();
	test_event_filter_strlist();
	test_event_filter_strlist_recursive();
	test_event_filter_strlist_global_events();
	test_event_filter_named_and_str();
	test_event_filter_named_or_str();
	test_event_filter_named_separate_from_str();
	test_event_filter_duration();
	test_event_filter_numbers();
	test_event_filter_ips();
	test_event_filter_size_values();
	test_event_filter_interval_values();
	test_event_filter_ambiguous_units();
	test_event_filter_timeval_values();
}
