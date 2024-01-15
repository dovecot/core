#include "lib.h"
#include "cpu-count.h"

#ifdef HAVE_SCHED_H
#  define __USE_GNU
#  include <sched.h>
#  ifdef HAVE_SYS_CPUSET_H
#    include <sys/cpuset.h>
#  endif
#endif

int cpu_count_get(int *cpu_count_r, const char **error_r)
{
	int result;
#if defined(HAVE_SCHED_GETAFFINITY)
	cpu_set_t cs;
	CPU_ZERO(&cs);
	if (sched_getaffinity(0, sizeof(cs), &cs) < 0) {
		*error_r = t_strdup_printf("sched_getaffinity() failed: %m");
		return -1;
	}
	result = CPU_COUNT(&cs);
#elif defined(HAVE_CPUSET_GETAFFINITY)
	cpuset_t cs;
	CPU_CLR(sizeof(cs), &cs);
	if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
			       sizeof(cs), &cs) < 0) {
		*error_r = t_strdup_printf("cpuset_getaffinity() failed: %m");
		return -1;
	}
	result = CPU_COUNT(&cs);
#else
	*cpu_count_r = 0;
	*error_r = "Cannot get CPU count";
	return -1;
#endif
	*cpu_count_r = result;
	return 0;
}
