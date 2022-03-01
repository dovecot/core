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

static void test_lib_event_reason_code(void)
{
	test_begin("event reason codes");
	test_assert_strcmp(event_reason_code("foo", "bar"), "foo:bar");
	test_assert_strcmp(event_reason_code("foo", "B A-r"), "foo:b_a_r");
	test_assert_strcmp(event_reason_code_prefix("foo", "x", "bar"), "foo:xbar");
	test_assert_strcmp(event_reason_code_prefix("foo", "", "bar"), "foo:bar");
	test_end();
}

void test_lib_event(void)
{
	test_event_strlist();
	test_lib_event_reason_code();
}

enum fatal_test_state fatal_lib_event(unsigned int stage)
{
	switch (stage) {
	case 0:
		test_begin("event reason codes - asserts");
		/* module: uppercase */
		test_expect_fatal_string("Invalid module");
		(void)event_reason_code("FOO", "bar");
		return FATAL_TEST_FAILURE;
	case 1:
		/* module: space */
		test_expect_fatal_string("Invalid module");
		(void)event_reason_code("f oo", "bar");
		return FATAL_TEST_FAILURE;
	case 2:
		/* module: - */
		test_expect_fatal_string("Invalid module");
		(void)event_reason_code("f-oo", "bar");
		return FATAL_TEST_FAILURE;
	case 3:
		/* module: empty */
		test_expect_fatal_string("module[0] != '\\0'");
		(void)event_reason_code("", "bar");
		return FATAL_TEST_FAILURE;
	case 4:
		/* name_prefix: uppercase */
		test_expect_fatal_string("Invalid name_prefix");
		(void)event_reason_code_prefix("module", "FOO", "bar");
		return FATAL_TEST_FAILURE;
	case 5:
		/* name_prefix: space */
		test_expect_fatal_string("Invalid name_prefix");
		(void)event_reason_code_prefix("module", "f oo", "bar");
		return FATAL_TEST_FAILURE;
	case 6:
		/* name_prefix: - */
		test_expect_fatal_string("Invalid name_prefix");
		(void)event_reason_code_prefix("module", "f-oo", "bar");
		return FATAL_TEST_FAILURE;
	case 7:
		/* name: empty */
		test_expect_fatal_string("(name[0] != '\\0')");
		(void)event_reason_code("foo:", "");
		return FATAL_TEST_FAILURE;
	default:
		test_end();
		return FATAL_TEST_FINISHED;
	}
}
