/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "event-filter.h"

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
	test_event_filter_clear_parent_fields();
}
