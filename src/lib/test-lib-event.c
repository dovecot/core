/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

static void test_event_strlist(void)
{
	test_begin("event strlist");
	struct event *e1 = event_create(NULL);
	event_strlist_append(e1, "key", "s1");
	event_strlist_append(e1, "key", "s2");
	struct event *e2 = event_create(e1);
	event_strlist_append(e2, "key", "s3");
	event_strlist_append(e2, "key", "s2");

	test_assert_strcmp(event_find_field_recursive_str(e1, "key"), "s1,s2");
	test_assert_strcmp(event_find_field_recursive_str(e2, "key"), "s3,s2,s1");

	const char *new_strlist[] = { "new1", "new2", "new2", "s2" };
	event_strlist_replace(e2, "key", new_strlist, N_ELEMENTS(new_strlist));
	test_assert_strcmp(event_find_field_recursive_str(e2, "key"), "new1,new2,s2,s1");

	struct event *e3 = event_create(NULL);
	event_strlist_copy_recursive(e3, e2, "key");
	test_assert_strcmp(event_find_field_recursive_str(e3, "key"), "new1,new2,s2,s1");
	event_unref(&e3);

	event_unref(&e1);
	event_unref(&e2);
	test_end();
}

void test_lib_event(void)
{
	test_event_strlist();
}
