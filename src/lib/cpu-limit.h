#ifndef CPU_LIMIT
#define CPU_LIMIT

struct cpu_limit;

enum cpu_limit_type {
	CPU_LIMIT_TYPE_USER	= BIT(0),
	CPU_LIMIT_TYPE_SYSTEM	= BIT(1),
};
#define CPU_LIMIT_TYPE_ALL (CPU_LIMIT_TYPE_USER | CPU_LIMIT_TYPE_SYSTEM)

/* Start tracking CPU usage. This internally uses setrlimit(RLIMIT_CPU) to
   trigger SIGXCPU to avoid constantly calling getrlimit() to check if the CPU
   usage has reached a limit. Once all limits created by this API are released,
   the original CPU resource limits are restored (if any).

   CPU time limits can be nested, i.e. they are never independent. The outer
   limits contain the bounded maximum limit for the inner limits. For example
   the code execution flow might be:
    - Set 30s CPU limit (outer limit)
    - Use up 5s of CPU
    - Set 40s CPU limit (inner limit)
    - Infinite loop
   The inner loop's limit won't even be reached here. After the inner loops
   runs for 25 seconds, the outer loop's 30s limit is reached. This causes
   both the inner and the other limit's cpu_limit_exceeded() to return TRUE.
   It's expected that the inner execution stops and returns back to the outer
   execution, which notices that the outer execution has also reached the limit.

   Another example where the inner limit is reached:
    - Set 30s CPU limit (outer limit)
    - Use up 5s of CPU
    - Set 10s CPU limit (inner limit)
    - Infinite loop
   Here the inner 10s limit is reached, and the inner execution stops. The
   outer execution could still run for another 15 seconds.

   Example usage:

   bool limit_reached = FALSE;
   limit = cpu_limit_init(5, CPU_LIMIT_TYPE_ALL);
   while (long_operation_iterate_once()) {
     if (cpu_limit_exceeded(limit)) {
       limit_reached = TRUE; // operation took >=5 secs
       break;
     }
   }
   cpu_limit_deinit(&limit);
*/
struct cpu_limit *
cpu_limit_init(unsigned int cpu_limit_secs, enum cpu_limit_type type);
void cpu_limit_deinit(struct cpu_limit **_climit);

/* Returns TRUE if the CPU limit has been exceeded for this limit or any of its
   parents. */
bool cpu_limit_exceeded(struct cpu_limit *climit);

unsigned int cpu_limit_get_usage_msecs(struct cpu_limit *climit,
				       enum cpu_limit_type type);

static inline unsigned int
cpu_limit_get_usage_secs(struct cpu_limit *climit, enum cpu_limit_type type)
{
	return cpu_limit_get_usage_msecs(climit, type) / 1000;
}

#endif
