#include "test-lib.h"
#include "str.h"
#include "backtrace-string.h"

static void test_backtrace_append(void)
{
	test_begin("backtrace_append");
	string_t *bt = t_str_new(128);
#if (defined(HAVE_LIBUNWIND))
        test_assert(backtrace_append(bt) == 0);
	/* Check that there's a usable function in the backtrace.
	   Note that this function may be inlined, so don't check for
	   test_backtrace_get() */
	test_assert(strstr(str_c(bt), "test_backtrace") != NULL);
	/* make sure the backtrace_append is not */
	test_assert(strstr(str_c(bt), " backtrace_append") == NULL);
#elif (defined(HAVE_BACKTRACE_SYMBOLS) && defined(HAVE_EXECINFO_H)) || \
      (defined(HAVE_WALKCONTEXT) && defined(HAVE_UCONTEXT_H))
	test_assert(backtrace_append(bt) == 0);
	/* it should have some kind of main in it */
	test_assert(strstr(str_c(bt), "main") != NULL);
#else
	/* should not work in this context */
	test_assert(backtrace_append(bt) == -1);
#endif
	test_end();
}

static void test_backtrace_get(void)
{
	test_begin("backtrace_get");
	const char *bt = NULL;
#if (defined(HAVE_LIBUNWIND))
        test_assert(backtrace_get(&bt) == 0);
	/* Check that there's a usable function in the backtrace.
	   Note that this function may be inlined, so don't check for
	   test_backtrace_get() */
        test_assert(strstr(bt, "test_backtrace") != NULL);
	/* make sure the backtrace_get is not */
	test_assert(strstr(bt, " backtrace_get") == NULL);
#elif (defined(HAVE_BACKTRACE_SYMBOLS) && defined(HAVE_EXECINFO_H)) || \
      (defined(HAVE_WALKCONTEXT) && defined(HAVE_UCONTEXT_H))
	test_assert(backtrace_get(&bt) == 0);
	/* it should have some kind of main in it */
	test_assert(strstr(bt, "main") != NULL);
#else
	/* should not work in this context */
	test_assert(backtrace_get(&bt) == -1);
#endif
	test_end();
}

void test_backtrace(void)
{
	test_backtrace_append();
	test_backtrace_get();
}
