/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "acl-api-private.h"

static void test_acl_rights_sort(void)
{
	struct acl_rights rights1 = {
		.rights = t_strsplit("a b a c d b", " "),
		.neg_rights = t_strsplit("e d c a a d b e", " "),
	};
	struct acl_rights rights2 = {
		.rights = t_strsplit("a c x", " "),
		.neg_rights = t_strsplit("b c y", " "),
	};
	struct acl_object obj = {
		.rights_pool = pool_alloconly_create("acl rights", 256)
	};
	const struct acl_rights *rights;

	test_begin("acl_rights_sort");
	t_array_init(&obj.rights, 8);

	/* try with zero rights */
	acl_rights_sort(&obj);
	test_assert(array_count(&obj.rights) == 0);

	/* try with just one right */
	array_push_back(&obj.rights, &rights1);
	acl_rights_sort(&obj);
	test_assert(array_count(&obj.rights) == 1);
	rights = array_idx(&obj.rights, 0);
	test_assert(acl_rights_cmp(rights, &rights1) == 0);

	/* try with two rights that don't have equal ID */
	struct acl_rights rights1_id2 = rights1;
	rights1_id2.identifier = "id2";
	array_push_back(&obj.rights, &rights1_id2);
	acl_rights_sort(&obj);
	test_assert(array_count(&obj.rights) == 2);
	rights = array_idx(&obj.rights, 0);
	test_assert(acl_rights_cmp(&rights[0], &rights1) == 0);
	test_assert(acl_rights_cmp(&rights[1], &rights1_id2) == 0);

	/* try with 3 rights where first has equal ID */
	array_push_back(&obj.rights, &rights2);
	acl_rights_sort(&obj);
	test_assert(array_count(&obj.rights) == 2);
	rights = array_idx(&obj.rights, 0);
	test_assert_strcmp(t_strarray_join(rights[0].rights, " "), "a b c d x");
	test_assert_strcmp(t_strarray_join(rights[0].neg_rights, " "), "a b c d e y");

	pool_unref(&obj.rights_pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_acl_rights_sort,
		NULL
	};
	return test_run(test_functions);
}
