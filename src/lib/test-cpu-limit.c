#include "test-lib.h"
#include "lib-signals.h"
#include "guid.h"
#include "time-util.h"
#include "cpu-limit.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

/* The CPU limits aren't exact. Allow this much leniency in the time
   comparisons. Note that system CPU usage can grow very large on loaded
   systems, so we're not checking its upper limit at all. */
#define ALLOW_MSECS_BELOW 500

static const char *const test_path = ".test.cpulimit";

static struct timeval get_cpu_time(enum cpu_limit_type type)
{
	struct rusage rusage;
	struct timeval cpu_usage = { 0, 0 };

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");
	if ((type & CPU_LIMIT_TYPE_USER) != 0)
		timeval_add(&cpu_usage, &rusage.ru_utime);
	if ((type & CPU_LIMIT_TYPE_SYSTEM) != 0)
		timeval_add(&cpu_usage, &rusage.ru_stime);
	return cpu_usage;
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

static void
test_cpu_limit_simple(enum cpu_limit_type type, const char *type_str)
{
	struct cpu_limit *climit;
	struct timeval usage, cpu;
	int diff_msecs;

	test_begin(t_strdup_printf("cpu limit - simple (%s)", type_str));

	lib_signals_init();
	climit = cpu_limit_init(2, type);
	usage = get_cpu_time(type);

	while (!cpu_limit_exceeded(climit))
		test_cpu_loop_once();

	cpu_limit_deinit(&climit);
	cpu = get_cpu_time(type);
	diff_msecs = timeval_diff_msecs(&cpu, &usage);
	test_assert_cmp(diff_msecs, >=, 2000 - ALLOW_MSECS_BELOW);

	lib_signals_deinit();
	test_end();
}

static void test_cpu_limit_nested(enum cpu_limit_type type, const char *type_str)
{
	struct cpu_limit *climit1, *climit2;
	struct timeval usage1, cpu;
	unsigned int n;
	int diff_msecs;

	test_begin(t_strdup_printf("cpu limit - nested (%s)", type_str));

	lib_signals_init();
	climit1 = cpu_limit_init(3, type);
	usage1 = get_cpu_time(type);

	while (!cpu_limit_exceeded(climit1) && !test_has_failed()) {
		climit2 = cpu_limit_init(1, type);

		while (!cpu_limit_exceeded(climit2) && !test_has_failed())
			test_cpu_loop_once();

		cpu_limit_deinit(&climit2);
	}

	cpu_limit_deinit(&climit1);
	cpu = get_cpu_time(type);
	diff_msecs = timeval_diff_msecs(&cpu, &usage1);
	test_assert_cmp(diff_msecs, >=, 3000 - ALLOW_MSECS_BELOW);

	lib_signals_deinit();
	test_end();

	test_begin(t_strdup_printf("cpu limit - nested2 (%s)", type_str));

	lib_signals_init();
	climit1 = cpu_limit_init(3, type);
	usage1 = get_cpu_time(type);

	n = 0;
	while (!cpu_limit_exceeded(climit1) && !test_has_failed()) {
		if (++n >= 3) {
			/* Consume last second in top cpu limit */
			test_cpu_loop_once();
			continue;
		}
		climit2 = cpu_limit_init(1, type);

		while (!cpu_limit_exceeded(climit2) && !test_has_failed())
			test_cpu_loop_once();

		cpu_limit_deinit(&climit2);
	}

	cpu_limit_deinit(&climit1);
	cpu = get_cpu_time(type);
	diff_msecs = timeval_diff_msecs(&cpu, &usage1);
	test_assert_cmp(diff_msecs, >=, 3000 - ALLOW_MSECS_BELOW);

	i_unlink_if_exists(test_path);
	lib_signals_deinit();
	test_end();
}

void test_cpu_limit(void)
{
	test_cpu_limit_simple(CPU_LIMIT_TYPE_USER, "user");
	/* the system cpu-limit tests take too long with valgrind */
	if (!ON_VALGRIND)
		test_cpu_limit_simple(CPU_LIMIT_TYPE_SYSTEM, "system");
	test_cpu_limit_simple(CPU_LIMIT_TYPE_ALL, "all");
	test_cpu_limit_nested(CPU_LIMIT_TYPE_USER, "user");
	if (!ON_VALGRIND)
		test_cpu_limit_nested(CPU_LIMIT_TYPE_SYSTEM, "system");
	test_cpu_limit_nested(CPU_LIMIT_TYPE_ALL, "all");
}
