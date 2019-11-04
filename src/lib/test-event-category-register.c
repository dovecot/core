/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "lib-event-private.h"
#include "failures-private.h"

/* we call a generic "unregister category function; to tell it what exact
 * behavior it should expect from lib-lib, we pass in one of the following
 * values
 */
enum unreg_expectation {
	UNREG_NOT_LAST,
	UNREG_LAST,
	UNREG_NOP,
};

#define CAT_NAME_PREFIX	"test-category"

/* pointer to a category we expect to be registered/unregistered */
static struct event_category *expected_callback_cat;
static bool callback_called;

static struct event *dummy_event;

static void check_category(struct event_category *cat)
{
	callback_called = TRUE;

	/* lib-lib called a callback with a NULL? (useless and a bug) */
	test_assert(cat != NULL);

	/* callback called, but didn't expect to be called? */
	test_assert(expected_callback_cat != NULL);

	/* test_assert() doesn't terminate, so avoid NULL ptr derefs later on */
	if ((cat == NULL) || (expected_callback_cat == NULL))
		return;

	/* check that the categories have the same values */
	test_assert(strcmp(cat->name, expected_callback_cat->name) == 0);
	test_assert(cat->internal == expected_callback_cat->internal);
}

static void check_cat_registered(const char *name, bool should_exist)
{
	struct event_category *cat;

	callback_called = FALSE;
	cat = event_category_find_registered(name);
	test_assert(callback_called == FALSE);

	test_assert((cat != NULL) == should_exist);
}

static void register_cat(struct event_category *newcat,
			 struct event_category *expcat)
{
	/* start with a known state - no regs expected */
	expected_callback_cat = NULL;
	callback_called = FALSE;

	dummy_event = event_create(NULL);
	test_assert(callback_called == FALSE);

	/* we expect a registration only when adding a cat */
	expected_callback_cat = (expcat);
	event_add_category(dummy_event, (newcat));
	expected_callback_cat = NULL;

	/* check that all went well */
	test_assert(callback_called == (expcat != NULL));
	test_assert((newcat)->internal != NULL);
	test_assert(event_category_find_registered((newcat)->name) != NULL);

	/* clean up */
	event_unref(&dummy_event);
}

static void unregister_cat(struct event_category *cat,
			   enum unreg_expectation expectation)
{
	/* sanity check that cat is set up as expected */
	switch (expectation) {
	case UNREG_NOT_LAST:
		/* must be registered to unregister */
		test_assert(event_category_find_registered((cat)->name) != NULL);
		expected_callback_cat = NULL;
		break;

	case UNREG_LAST:
		/* must be registered to unregister */
		test_assert(event_category_find_registered((cat)->name) != NULL);
		expected_callback_cat = cat;
		break;

	case UNREG_NOP:
		/* must not be registered for no-op */
		/* event_category_find_registered(cat->name) should return
		   NULL, but since we don't actually unregister this lookup
		   would fail.  Therefore, we skip it. */
		expected_callback_cat = NULL;
		break;
	}

	/* Note: We don't actually have a way to unregister categories.  We
	   keep the above checks and the calls to this function as a form of
	   documentation of how unregistering should work. */
}

static void test_event_category_1ptr_null(void)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-1ptr-null"
	static struct event_category cat = { .name = CAT_NAME_0 };

	test_begin("event category rereg: same ptr, NULL parent");

	check_cat_registered(CAT_NAME_0, FALSE);
	register_cat(&cat, &cat);
	register_cat(&cat, NULL);
	check_cat_registered(CAT_NAME_0, TRUE);

	unregister_cat(&cat, UNREG_LAST);
	unregister_cat(&cat, UNREG_NOP);

	test_end();
#undef CAT_NAME_0
}

static void test_event_category_1ptr_nonnull(void)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-1ptr-nonnull-0"
#define CAT_NAME_1	CAT_NAME_PREFIX "-1ptr-nonnull-1"
	static struct event_category cat = { .name = CAT_NAME_0 };
	static struct event_category cat_with_parent = { .name = CAT_NAME_1, .parent = &cat };

	test_begin("event category rereg: same ptr, non-NULL parent");

	check_cat_registered(CAT_NAME_0, FALSE);
	check_cat_registered(CAT_NAME_1, FALSE);
	register_cat(&cat, &cat);
	register_cat(&cat_with_parent, &cat_with_parent);
	register_cat(&cat_with_parent, NULL);
	check_cat_registered(CAT_NAME_0, TRUE);
	check_cat_registered(CAT_NAME_1, TRUE);

	unregister_cat(&cat_with_parent, UNREG_LAST);
	unregister_cat(&cat_with_parent, UNREG_NOP);
	/* NOTE: we must unreg children before parent cats */
	unregister_cat(&cat, UNREG_LAST);
	unregister_cat(&cat, UNREG_NOP);

	test_end();
#undef CAT_NAME_0
#undef CAT_NAME_1
}

static void test_event_category_2ptr_null(void)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-2ptr-null"
	static struct event_category cat0 = { .name = CAT_NAME_0 };
	static struct event_category cat1 = { .name = CAT_NAME_0 };

	test_begin("event category rereg: different ptr, NULL parent");

	check_cat_registered(CAT_NAME_0, FALSE);
	register_cat(&cat0, &cat0);
	register_cat(&cat1, NULL);
	check_cat_registered(CAT_NAME_0, TRUE);

	unregister_cat(&cat0, UNREG_NOT_LAST);
	unregister_cat(&cat1, UNREG_LAST);
	unregister_cat(&cat0, UNREG_NOP);
	unregister_cat(&cat1, UNREG_NOP);

	test_end();
#undef CAT_NAME_0
}

static void test_event_category_2ptr_nonnull_same(void)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-2ptr-nonnull-same-0"
#define CAT_NAME_1	CAT_NAME_PREFIX "-2ptr-nonnull-same-1"
	static struct event_category cat = { .name = CAT_NAME_0 };
	static struct event_category cat_with_parent0 = { .name = CAT_NAME_1, .parent = &cat };
	static struct event_category cat_with_parent1 = { .name = CAT_NAME_1, .parent = &cat };

	test_begin("event category rereg: different ptr, same non-NULL parent");

	check_cat_registered(CAT_NAME_0, FALSE);
	check_cat_registered(CAT_NAME_1, FALSE);
	register_cat(&cat, &cat);
	register_cat(&cat_with_parent0, &cat_with_parent0);
	register_cat(&cat_with_parent1, NULL);
	check_cat_registered(CAT_NAME_0, TRUE);
	check_cat_registered(CAT_NAME_1, TRUE);

	unregister_cat(&cat_with_parent0, UNREG_NOT_LAST);
	unregister_cat(&cat_with_parent1, UNREG_LAST);
	unregister_cat(&cat_with_parent0, UNREG_NOP);
	unregister_cat(&cat_with_parent1, UNREG_NOP);
	/* NOTE: we must unreg children before parent cats */
	unregister_cat(&cat, UNREG_LAST);
	unregister_cat(&cat, UNREG_NOP);

	test_end();
#undef CAT_NAME_0
#undef CAT_NAME_1
}

static void test_event_category_2ptr_nonnull_similar(void)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-2ptr-nonnull-similar-0"
#define CAT_NAME_1	CAT_NAME_PREFIX "-2ptr-nonnull-similar-1"
	static struct event_category cat0 = { .name = CAT_NAME_0 };
	static struct event_category cat1 = { .name = CAT_NAME_0 };
	static struct event_category cat_with_parent0 = { .name = CAT_NAME_1, .parent = &cat0 };
	static struct event_category cat_with_parent1 = { .name = CAT_NAME_1, .parent = &cat1 };

	test_begin("event category rereg: different ptr, similar non-NULL parent");

	check_cat_registered(CAT_NAME_0, FALSE);
	check_cat_registered(CAT_NAME_1, FALSE);
	register_cat(&cat0, &cat0);
	register_cat(&cat1, NULL);
	register_cat(&cat_with_parent0, &cat_with_parent0);
	register_cat(&cat_with_parent1, NULL);
	check_cat_registered(CAT_NAME_0, TRUE);
	check_cat_registered(CAT_NAME_1, TRUE);

	unregister_cat(&cat_with_parent0, UNREG_NOT_LAST);
	unregister_cat(&cat_with_parent1, UNREG_LAST);
	unregister_cat(&cat_with_parent0, UNREG_NOP);
	unregister_cat(&cat_with_parent1, UNREG_NOP);
	/* NOTE: we must unreg children before parent cats */
	unregister_cat(&cat0, UNREG_NOT_LAST);
	unregister_cat(&cat1, UNREG_LAST);
	unregister_cat(&cat0, UNREG_NOP);
	unregister_cat(&cat1, UNREG_NOP);

	test_end();
#undef CAT_NAME_0
#undef CAT_NAME_1
}

void test_event_category_register(void)
{
	event_category_register_callback(check_category);

	/*
	 * registering/unregistering the same exact category struct (i.e.,
	 * the pointer is the same) is a no-op after the first call
	 */
	test_event_category_1ptr_null();
	test_event_category_1ptr_nonnull();

	/*
	 * registering/unregistering two different category structs (i.e.,
	 * the pointers are different) is a almost a no-op
	 */
	test_event_category_2ptr_null();
	test_event_category_2ptr_nonnull_same();
	test_event_category_2ptr_nonnull_similar();

	event_category_unregister_callback(check_category);
}

enum fatal_test_state fatal_event_category_register(unsigned int stage)
{
#define CAT_NAME_0	CAT_NAME_PREFIX "-2ptr-nonnull-different-0"
#define CAT_NAME_1	CAT_NAME_PREFIX "-2ptr-nonnull-different-1"
#define CAT_NAME_2	CAT_NAME_PREFIX "-2ptr-nonnull-different-2"
	static struct event_category cat_no_parent0 = { .name = CAT_NAME_0 };
	static struct event_category cat_parent0 = { .name = CAT_NAME_1, .parent = &cat_no_parent0 };
	static struct event_category cat_other = { .name = CAT_NAME_2 };
	static struct event_category cat_other_parent = { .name = CAT_NAME_1, .parent = &cat_other };

	/* we have only one fatal stage at this point */
	switch (stage) {
	case 0:
		event_category_register_callback(check_category);

		test_begin("event category rereg: different ptr, different non-NULL parent");

		check_cat_registered(CAT_NAME_0, FALSE);
		check_cat_registered(CAT_NAME_1, FALSE);
		check_cat_registered(CAT_NAME_2, FALSE);
		register_cat(&cat_no_parent0, &cat_no_parent0);
		register_cat(&cat_other, &cat_other);
		register_cat(&cat_parent0, &cat_parent0);

		test_expect_fatal_string("event category parent mismatch detected");
		register_cat(&cat_other_parent, NULL); /* expected panic */

		return FATAL_TEST_FAILURE;
	case 1:
		event_unref(&dummy_event);

		unregister_cat(&cat_parent0, UNREG_LAST);
		unregister_cat(&cat_parent0, UNREG_NOP);
		unregister_cat(&cat_other, UNREG_LAST);
		unregister_cat(&cat_other, UNREG_NOP);
		/* NOTE: we must unreg children before parent cats */
		unregister_cat(&cat_no_parent0, UNREG_LAST);
		unregister_cat(&cat_no_parent0, UNREG_NOP);

		test_end();

		event_category_unregister_callback(check_category);

		return FATAL_TEST_FINISHED;

	default:
		return FATAL_TEST_ABORT;
	}
#undef CAT_NAME_0
#undef CAT_NAME_1
#undef CAT_NAME_2
}
