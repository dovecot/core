#include "test-lib.h"
#include "lib-signals.h"
#include "guid.h"
#include "time-util.h"
#include "cpu-limit.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

static bool limit_exceeded1, limit_exceeded2;
static const char *const test_path = ".test.cpulimit";

static void cpu_limit_callback1(void *context ATTR_UNUSED)
{
	limit_exceeded1 = TRUE;
}

static void cpu_limit_callback2(void *context ATTR_UNUSED)
{
	limit_exceeded2 = TRUE;
}

static time_t get_cpu_time(void)
{
	struct rusage rusage;
	struct timeval cpu_usage;

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");
	cpu_usage = rusage.ru_utime;
	timeval_add(&cpu_usage, &rusage.ru_stime);

	return timeval_round(&cpu_usage);
}

static void test_cpu_loop_once(void)
{
	guid_128_t guid;

	/* consume some user CPU */
	for (unsigned int i = 0; i < 10000; i++)
		guid_128_generate(guid);
	/* consume some system CPU */
	int fd = creat(test_path, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", test_path);
	if (write(fd, guid, sizeof(guid)) < 0)
		i_fatal("write(%s) failed: %m", test_path);
	i_close_fd(&fd);
}

static void test_cpu_limit_simple(void)
{
	struct cpu_limit *climit;
	time_t usage;

	test_begin("cpu limit - simple");

	lib_signals_init();
	climit = cpu_limit_init(2, cpu_limit_callback1, NULL);
	usage = get_cpu_time();

	limit_exceeded1 = FALSE;
	while (!limit_exceeded1)
		test_cpu_loop_once();

	cpu_limit_deinit(&climit);
	test_assert((get_cpu_time() - usage) == 2);

	lib_signals_deinit();
	test_end();
}

static void test_cpu_limit_nested(void)
{
	struct cpu_limit *climit1, *climit2;
	time_t usage1, usage2;
	unsigned int n;

	test_begin("cpu limit - nested");

	lib_signals_init();
	climit1 = cpu_limit_init(3, cpu_limit_callback1, NULL);
	usage1 = get_cpu_time();

	limit_exceeded1 = FALSE;
	while (!limit_exceeded1 && !test_has_failed()) {
		climit2 = cpu_limit_init(1, cpu_limit_callback2, NULL);
		usage2 = get_cpu_time();

		limit_exceeded2 = FALSE;
		while (!limit_exceeded2 && !test_has_failed())
			test_cpu_loop_once();

		cpu_limit_deinit(&climit2);
		test_assert((get_cpu_time() - usage2) == 1);
	}

	cpu_limit_deinit(&climit1);
	test_assert((get_cpu_time() - usage1) == 3);

	lib_signals_deinit();
	test_end();

	test_begin("cpu limit - nested2");

	lib_signals_init();
	climit1 = cpu_limit_init(3, cpu_limit_callback1, NULL);
	usage1 = get_cpu_time();

	limit_exceeded1 = FALSE;
	n = 0;
	while (!limit_exceeded1 && !test_has_failed()) {
		if (++n >= 3) {
			/* Consume last second in top cpu limit */
			test_cpu_loop_once();
			continue;
		}
		climit2 = cpu_limit_init(1, cpu_limit_callback2, NULL);
		usage2 = get_cpu_time();

		limit_exceeded2 = FALSE;
		while (!limit_exceeded2 && !test_has_failed())
			test_cpu_loop_once();

		cpu_limit_deinit(&climit2);
		test_assert((get_cpu_time() - usage2) == 1);
	}

	cpu_limit_deinit(&climit1);
	test_assert((get_cpu_time() - usage1) == 3);

	i_unlink_if_exists(test_path);
	lib_signals_deinit();
	test_end();
}

void test_cpu_limit(void)
{
	test_cpu_limit_simple();
	test_cpu_limit_nested();
}
