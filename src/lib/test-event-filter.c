/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "event-filter.h"

static void test_event_filter_override_parent_fields(void)
{
	struct event_filter *filter;
	struct event_filter_field parent_query_fields[] = {
		{ .key = "str", .value = "parent_str" },
		{ .key = "int1", .value = "0" },
		{ .key = "int2", .value = "5" },
		{ .key = NULL, .value = NULL }
	};
	const struct event_filter_query parent_query = {
		.fields = parent_query_fields,
	};
	struct event_filter_field child_query_fields[] = {
		{ .key = "str", .value = "child_str" },
		{ .key = "int1", .value = "6" },
		{ .key = "int2", .value = "0" },
		{ .key = NULL, .value = NULL }
	};
	const struct event_filter_query child_query = {
		.fields = child_query_fields,
	};
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};

	test_begin("event filter: override parent fields");

	struct event *parent = event_create(NULL);
	event_add_str(parent, "str", "parent_str");
	event_add_int(parent, "int1", 0);
	event_add_int(parent, "int2", 5);

	struct event *child = event_create(NULL);
	event_add_str(child, "str", "child_str");
	event_add_int(child, "int1", 6);
	event_add_int(child, "int2", 0);

	filter = event_filter_create();
	event_filter_add(filter, &parent_query);
	test_assert(event_filter_match(filter, parent, &failure_ctx));
	test_assert(!event_filter_match(filter, child, &failure_ctx));
	event_filter_unref(&filter);

	filter = event_filter_create();
	event_filter_add(filter, &child_query);
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
	struct event_filter_field filter_fields[] = {
		{ .key = "", .value = "*" },
		{ .key = NULL, .value = NULL }
	};
	const struct event_filter_query query = {
		.fields = filter_fields,
	};
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG
	};
	const char *keys[] = { "str", "int" };

	test_begin("event filter: clear parent fields");

	struct event *parent = event_create(NULL);
	event_add_str(parent, "str", "parent_str");
	event_add_int(parent, "int", 0);

	struct event *child = event_create(NULL);
	event_field_clear(child, "str");
	event_field_clear(child, "int");

	for (unsigned int i = 0; i < N_ELEMENTS(keys); i++) {
		filter_fields[0].key = keys[i];
		filter = event_filter_create();
		event_filter_add(filter, &query);

		test_assert_idx(event_filter_match(filter, parent, &failure_ctx), i);
		test_assert_idx(!event_filter_match(filter, child, &failure_ctx), i);
		event_filter_unref(&filter);
	}

	event_unref(&parent);
	event_unref(&child);
	test_end();
}

void test_event_filter(void)
{
	test_event_filter_override_parent_fields();
	test_event_filter_clear_parent_fields();
}
