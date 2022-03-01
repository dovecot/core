/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "event-filter.h"

static void filter_merge(const char *parent_str, const char *child_str)
{
	struct event_filter *parent, *child;
	const char *test_name, *error;
	string_t *out = t_str_new(128);

	test_name = t_strdup_printf("parent %s, child %s",
				    (parent_str == NULL) ? "NULL" : parent_str,
				    (child_str == NULL) ? "NULL" : child_str);

	parent = event_filter_create();
	child = event_filter_create();

	/* prime the filters with an expression */
	if (parent_str != NULL) {
		test_out_quiet(t_strdup_printf("%s:parent", test_name),
			       event_filter_parse(parent_str, parent, &error) == 0);
	}
	if (child_str != NULL) {
		test_out_quiet(t_strdup_printf("%s:child", test_name),
			       event_filter_parse(child_str, child, &error) == 0);
	}
	/* merge */
	event_filter_merge(parent, child);

	/* export - to visit/deref everything in the filter */
	event_filter_export(parent, out);
	event_filter_export(child, out);

	event_filter_unref(&parent);
	event_filter_unref(&child);
}

void test_event_filter_merge(void)
{
	static const char *inputs[] = {
		NULL,
		/* event name */
		"event=\"bar\"",
		"event=\"\"",
		/* category */
		"category=\"bar\"",
		"category=\"\"",
		/* source location */
		"source_location=\"bar:123\"",
		"source_location=\"bar\"",
		"source_location=\"\"",
		/* field */
		"foo=\"bar\"",
		"foo=\"\"",
	};
	unsigned int i, j;

	test_begin("event filter merge");
	for (i = 0; i < N_ELEMENTS(inputs); i++) {
		for (j = 0; j < N_ELEMENTS(inputs); j++) T_BEGIN {
			filter_merge(inputs[i], inputs[j]);
		} T_END;
	}
	test_end();
}
