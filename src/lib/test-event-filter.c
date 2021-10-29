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
}
