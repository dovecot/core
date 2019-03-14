#include "test-lib.h"
#include "backtrace-string.h"
#include <setjmp.h>
#include <signal.h>

static void test_backtrace_get(void)
{
	test_begin("backtrace_get");
	const char *bt = NULL;
#if (defined(HAVE_LIBUNWIND))
        test_assert(backtrace_get(&bt) == 0);
	/* check that this function is there */
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
	test_backtrace_get();
}
