/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* acl-cache only reaches into acl_backend for default_aclmask, so it can be
   tested with a minimal backend and without any mail storage. */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "acl-api-private.h"
#include "acl-cache.h"

#define TEST_OBJNAME "Test"
#define TEST_OBJNAME2 "Test2"

/* all_mailbox_rights[] in declaration order, which is also the order that
   acl_backend_mask_get_names() returns them in once they are registered in
   that order by test_acl_cache_init() */
#define TEST_RIGHTS_ALL \
	"lookup read write write-seen write-deleted insert post expunge " \
	"create delete admin"

struct test_validity {
	unsigned int value;
};

struct test_acl_cache {
	struct acl_backend backend;
	pool_t pool;
};

/* NULL-terminated const char *const[] literal */
#define TEST_RIGHTS(...) ((const char *const []){ __VA_ARGS__, NULL })

static struct acl_cache *
test_acl_cache_init(struct test_acl_cache *tc_r,
		    const char *const *default_rights)
{
	i_zero(tc_r);
	tc_r->pool = pool_alloconly_create("test acl cache", 1024);
	tc_r->backend.pool = tc_r->pool;
	tc_r->backend.cache = acl_cache_init(&tc_r->backend,
					     sizeof(struct test_validity));

	/* register the standard rights first, so that the mask bit order -
	   and with it acl_backend_mask_get_names() output - is predictable */
	for (unsigned int i = 0; all_mailbox_rights[i] != NULL; i++) {
		(void)acl_cache_right_lookup(tc_r->backend.cache,
					     all_mailbox_rights[i]);
	}

	tc_r->backend.default_rights = default_rights;
	tc_r->backend.default_aclmask =
		acl_cache_mask_init(tc_r->backend.cache, tc_r->pool,
				    default_rights);
	return tc_r->backend.cache;
}

static void test_acl_cache_deinit(struct test_acl_cache *tc)
{
	acl_cache_mask_deinit(&tc->backend.default_aclmask);
	acl_cache_deinit(&tc->backend.cache);
	pool_unref(&tc->pool);
}

static const char *
mask_str(struct acl_backend *backend, const struct acl_mask *mask)
{
	const char *const *names;

	if (mask == NULL)
		return "(null)";
	names = acl_backend_mask_get_names(backend, mask,
					   pool_datastack_create());
	return t_strarray_join(names, " ");
}

static const char *my_rights_str(struct test_acl_cache *tc, const char *objname)
{
	return mask_str(&tc->backend,
			acl_cache_get_my_rights(tc->backend.cache, objname));
}

static void
test_acl_cache_do_update(struct acl_cache *cache, const char *objname,
			 enum acl_modify_mode modify_mode,
			 const char *const *rights,
			 enum acl_modify_mode neg_modify_mode,
			 const char *const *neg_rights)
{
	struct acl_rights_update update = {
		.modify_mode = modify_mode,
		.neg_modify_mode = neg_modify_mode,
		.rights = {
			.id_type = ACL_ID_USER,
			.identifier = "testuser",
			.rights = rights,
			.neg_rights = neg_rights,
		},
	};

	acl_cache_update(cache, objname, &update);
}

static void test_acl_cache_right_lookup(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);
	const char *const *names;
	unsigned int count, idx;

	test_begin("acl_cache_right_lookup()");
	/* the standard rights got indexes 0.. in registration order */
	for (unsigned int i = 0; all_mailbox_rights[i] != NULL; i++) {
		test_assert_cmp_idx(acl_cache_right_lookup(
			cache, all_mailbox_rights[i]), ==, i, i);
	}

	/* an unknown right gets a new index, and keeps it */
	idx = acl_cache_right_lookup(cache, "custom");
	test_assert_cmp(idx, ==, str_array_length(all_mailbox_rights));
	test_assert_cmp(acl_cache_right_lookup(cache, "custom"), ==, idx);
	test_assert_cmp(acl_cache_right_lookup(cache, "custom2"), ==, idx + 1);

	names = acl_cache_get_names(cache, &count);
	test_assert_cmp(count, ==, str_array_length(all_mailbox_rights) + 2);
	test_assert_strcmp(names[0], MAIL_ACL_LOOKUP);
	test_assert_strcmp(names[idx], "custom");
	test_assert_strcmp(names[idx + 1], "custom2");

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_mask(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);
	struct acl_mask *mask;
	unsigned int lookup_idx, admin_idx, custom_idx;

	test_begin("acl_cache_mask_init()");
	lookup_idx = acl_cache_right_lookup(cache, MAIL_ACL_LOOKUP);
	admin_idx = acl_cache_right_lookup(cache, MAIL_ACL_ADMIN);

	mask = acl_cache_mask_init(cache, tc.pool,
				   TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_assert(acl_cache_mask_isset(mask, lookup_idx));
	test_assert(!acl_cache_mask_isset(mask, admin_idx));
	test_assert_strcmp(mask_str(&tc.backend, mask), "lookup read");
	acl_cache_mask_deinit(&mask);

	/* an empty mask has nothing set, and out-of-range indexes are
	   simply not set rather than a buffer overrun */
	mask = acl_cache_mask_init(cache, tc.pool, empty_str_array);
	test_assert_cmp(mask->size, ==, 0);
	test_assert(!acl_cache_mask_isset(mask, lookup_idx));
	test_assert(!acl_cache_mask_isset(mask, 12345));
	test_assert_strcmp(mask_str(&tc.backend, mask), "");
	acl_cache_mask_deinit(&mask);

	/* unknown right names are registered on the fly */
	mask = acl_cache_mask_init(cache, tc.pool,
				   TEST_RIGHTS(MAIL_ACL_LOOKUP, "custom"));
	custom_idx = acl_cache_right_lookup(cache, "custom");
	test_assert(acl_cache_mask_isset(mask, custom_idx));
	test_assert_strcmp(mask_str(&tc.backend, mask), "lookup custom");
	acl_cache_mask_deinit(&mask);

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_validity(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);
	struct test_validity validity = { .value = 1234 };
	struct test_validity *got;

	test_begin("acl_cache_set_validity()");
	test_assert(acl_cache_get_validity(cache, TEST_OBJNAME) == NULL);

	acl_cache_set_validity(cache, TEST_OBJNAME, &validity);
	got = acl_cache_get_validity(cache, TEST_OBJNAME);
	test_assert(got != &validity);
	test_assert(got != NULL && got->value == 1234);

	/* setting the validity for a name that has no rights yet creates a
	   negative cache entry, so the rights still look unknown */
	test_assert(acl_cache_get_my_rights(cache, TEST_OBJNAME) == NULL);

	/* updating it keeps the object, i.e. doesn't reset to a negative
	   entry */
	validity.value = 4321;
	acl_cache_set_validity(cache, TEST_OBJNAME, &validity);
	got = acl_cache_get_validity(cache, TEST_OBJNAME);
	test_assert(got != NULL && got->value == 4321);

	acl_cache_flush(cache, TEST_OBJNAME);
	test_assert(acl_cache_get_validity(cache, TEST_OBJNAME) == NULL);

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_update_replace(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache =
		test_acl_cache_init(&tc, TEST_RIGHTS(MAIL_ACL_ADMIN));

	test_begin("acl_cache_update() replace");
	test_assert(acl_cache_get_my_rights(cache, TEST_OBJNAME) == NULL);

	/* REPLACE on a new object ignores the backend default rights */
	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ),
				 ACL_MODIFY_MODE_REPLACE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "lookup read");

	/* replacing again drops the previous rights */
	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_INSERT),
				 ACL_MODIFY_MODE_REPLACE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "insert");

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_update_defaults(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache =
		test_acl_cache_init(&tc, TEST_RIGHTS(MAIL_ACL_LOOKUP,
						     MAIL_ACL_READ));

	test_begin("acl_cache_update() defaults");
	/* a non-REPLACE update on a new object starts from the backend's
	   default rights */
	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_ADD,
				 TEST_RIGHTS(MAIL_ACL_INSERT),
				 ACL_MODIFY_MODE_ADD, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME),
			   "lookup read insert");

	/* the default mask itself must not have been modified */
	test_assert_strcmp(mask_str(&tc.backend, tc.backend.default_aclmask),
			   "lookup read");

	/* REMOVE also starts from the defaults */
	test_acl_cache_do_update(cache, TEST_OBJNAME2,
				 ACL_MODIFY_MODE_REMOVE,
				 TEST_RIGHTS(MAIL_ACL_READ),
				 ACL_MODIFY_MODE_REMOVE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME2), "lookup");

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_update_incremental(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);

	test_begin("acl_cache_update() add/remove");
	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_LOOKUP),
				 ACL_MODIFY_MODE_REPLACE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "lookup");

	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_ADD,
				 TEST_RIGHTS(MAIL_ACL_READ, MAIL_ACL_INSERT),
				 ACL_MODIFY_MODE_ADD, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME),
			   "lookup read insert");

	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_REMOVE,
				 TEST_RIGHTS(MAIL_ACL_LOOKUP),
				 ACL_MODIFY_MODE_REMOVE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "read insert");

	/* removing a right that isn't set changes nothing */
	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_REMOVE,
				 TEST_RIGHTS(MAIL_ACL_ADMIN),
				 ACL_MODIFY_MODE_REMOVE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "read insert");

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_update_negative(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);

	test_begin("acl_cache_update() negative rights");
	/* negative rights override the positive ones */
	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ,
					     MAIL_ACL_INSERT),
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_READ));
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "lookup insert");

	/* adding a positive right that is negated stays negated */
	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_ADD,
				 TEST_RIGHTS(MAIL_ACL_READ),
				 ACL_MODIFY_MODE_ADD, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), "lookup insert");

	/* until the negative right is removed */
	test_acl_cache_do_update(cache, TEST_OBJNAME, ACL_MODIFY_MODE_ADD,
				 NULL, ACL_MODIFY_MODE_REMOVE,
				 TEST_RIGHTS(MAIL_ACL_READ));
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME),
			   "lookup read insert");

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_flush(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, empty_str_array);
	struct test_validity validity = { .value = 1 };

	test_begin("acl_cache_flush()");
	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_LOOKUP),
				 ACL_MODIFY_MODE_REPLACE, NULL);
	acl_cache_set_validity(cache, TEST_OBJNAME, &validity);
	test_acl_cache_do_update(cache, TEST_OBJNAME2,
				 ACL_MODIFY_MODE_REPLACE,
				 TEST_RIGHTS(MAIL_ACL_READ),
				 ACL_MODIFY_MODE_REPLACE, NULL);
	acl_cache_set_validity(cache, TEST_OBJNAME2, &validity);

	/* flushing one object leaves the other one alone */
	acl_cache_flush(cache, TEST_OBJNAME);
	test_assert(acl_cache_get_validity(cache, TEST_OBJNAME) == NULL);
	test_assert(acl_cache_get_my_rights(cache, TEST_OBJNAME) == NULL);
	test_assert(acl_cache_get_validity(cache, TEST_OBJNAME2) != NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME2), "read");

	/* flushing an unknown object is a no-op */
	acl_cache_flush(cache, "nonexistent");

	acl_cache_flush_all(cache);
	test_assert(acl_cache_get_validity(cache, TEST_OBJNAME2) == NULL);
	test_assert(acl_cache_get_my_rights(cache, TEST_OBJNAME2) == NULL);

	/* the right name mapping survives a flush */
	test_assert_cmp(acl_cache_right_lookup(cache, MAIL_ACL_LOOKUP), ==, 0);

	test_acl_cache_deinit(&tc);
	test_end();
}

static void test_acl_cache_all_rights(void)
{
	struct test_acl_cache tc;
	struct acl_cache *cache = test_acl_cache_init(&tc, all_mailbox_rights);

	test_begin("acl_cache all rights");
	test_assert_strcmp(mask_str(&tc.backend, tc.backend.default_aclmask),
			   TEST_RIGHTS_ALL);

	test_acl_cache_do_update(cache, TEST_OBJNAME,
				 ACL_MODIFY_MODE_REPLACE, all_mailbox_rights,
				 ACL_MODIFY_MODE_REPLACE, NULL);
	test_assert_strcmp(my_rights_str(&tc, TEST_OBJNAME), TEST_RIGHTS_ALL);

	for (unsigned int i = 0; all_mailbox_rights[i] != NULL; i++) {
		const struct acl_mask *mask =
			acl_cache_get_my_rights(cache, TEST_OBJNAME);
		test_assert_idx(mask != NULL && acl_cache_mask_isset(mask, i),
				i);
	}

	test_acl_cache_deinit(&tc);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_acl_cache_right_lookup,
		test_acl_cache_mask,
		test_acl_cache_validity,
		test_acl_cache_update_replace,
		test_acl_cache_update_defaults,
		test_acl_cache_update_incremental,
		test_acl_cache_update_negative,
		test_acl_cache_flush,
		test_acl_cache_all_rights,
		NULL
	};
	return test_run(test_functions);
}
