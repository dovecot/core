#ifndef CPU_LIMIT
#define CPU_LIMIT

struct cpu_limit;

enum cpu_limit_type {
	CPU_LIMIT_TYPE_USER	= BIT(0),
	CPU_LIMIT_TYPE_SYSTEM	= BIT(1),
};
#define CPU_LIMIT_TYPE_ALL (CPU_LIMIT_TYPE_USER | CPU_LIMIT_TYPE_SYSTEM)

typedef void cpu_limit_callback_t(void *context);

/* Call the callback when the CPU time limit is exceeded. The callback is called
   in signal handler context, so be careful. The limit is enforced until
   cpu_limit_deinit() is called. This uses setrlimit() with RLIMIT_CPU
   internally, which counts both user and system CPU time. Once all limits
   created by this API are released, the original CPU resource limits are
   restored (if any).

   CPU time limits can be nested, i.e. they are never independent. The outer
   limits contain the bounded maximum limit for the inner limits. For example
   the code execution flow might be:
    - Set 30s CPU limit (outer limit)
    - Use up 5s of CPU
    - Set 40s CPU limit (inner limit)
    - Infinite loop
   The inner loop's limit won't even be reached here. After the inner loops
   runs for 25 seconds, the outer loop's 30s limit is reached. This causes
   both the inner and the other limit's callback to be called. It's expected
   that the inner execution stops and returns back to the outer execution,
   which notices that the outer execution has also reached the limit.

   Another example where the inner limit is reached:
    - Set 30s CPU limit (outer limit)
    - Use up 5s of CPU
    - Set 10s CPU limit (inner limit)
    - Infinite loop
   Here the inner 10s limit is reached, and the inner execution stops. The
   outer execution could still run for another 15 seconds.
 */
struct cpu_limit *
cpu_limit_init(unsigned int cpu_limit_sec,
	       cpu_limit_callback_t *callback, void *context);
#define cpu_limit_init(cpu_limit_sec, callback, context) \
	cpu_limit_init(cpu_limit_sec - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(cpu_limit_callback_t *)callback, context)
void cpu_limit_deinit(struct cpu_limit **_climit);

unsigned int cpu_limit_get_usage_msecs(struct cpu_limit *climit,
				       enum cpu_limit_type type);

static inline unsigned int
cpu_limit_get_usage_secs(struct cpu_limit *climit, enum cpu_limit_type type)
{
	return cpu_limit_get_usage_msecs(climit, type) / 1000;
}

#endif
