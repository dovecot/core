/* Copyright (c) 2001-2016 Dovecot authors, see the included COPYING file */

/* Unit tests for failure helpers */

#include "test-lib.h"
#include "failures.h"

static int handlers_set_me;

static void test_failures_handler(const struct failure_context *ctx,
				  const char *format ATTR_UNUSED,
				  va_list args ATTR_UNUSED)
{
	handlers_set_me = ctx->type;
}
static void test_get_set_handlers(void)
{
	failure_callback_t *handlers[4];
	test_begin("get_handlers");
	i_get_failure_handlers(handlers, handlers+1, handlers+2, handlers+3);
	test_end();

	test_begin("set_handlers");

	i_set_debug_handler(&test_failures_handler);
	i_debug("If you see this debug, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_DEBUG);
	i_set_debug_handler(handlers[3]);

	i_set_info_handler(&test_failures_handler);
	i_info("If you see this info, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_INFO);
	i_set_info_handler(handlers[2]);

	i_set_error_handler(&test_failures_handler);
	i_warning("If you see this warning, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_WARNING);
	i_error("If you see this error, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_ERROR);
	i_set_error_handler(handlers[1]);

	//i_set_fatal_handler(&test_failures_handler);
	//i_fatal("If you see this fatal, something's gone wrong");
	//test_assert(handlers_set_me == LOG_TYPE_FATAL);
	//i_set_fatal_handler(handlers[0]);

	test_end();
}
static void test_expected(void)
{
	test_begin("expected messages");
	test_expect_errors(1);
	i_warning("deliberate warning - not suppressed");
	test_expect_no_more_errors();
	test_end();
}
static void test_expected_str(void)
{
	test_begin("expected strings in messages");
	test_expect_error_string("be unhappy");
	i_error("deliberate error - suppressed - be unhappy if you see this");
	test_expect_no_more_errors();
	test_end();
}

void test_failures(void)
{
	test_get_set_handlers();
	test_expected();
	test_expected_str();
}
