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
   cpu_limit_deinit() is called. CPU time limits can be nested, upon which the
   outer time limit applies for all when it is shorter, while an inner limit
   will trigger alone (along with its children) when it is shorter. So, if e.g.
   both inner and outer limits are 5s, both will trigger at 5s. If the outer
   limit is 5s and the inner one is 10s, both with trigger at 5s. If the outer
   limit is 10s and the inner is 5, only the inner limit with trigger at 5s.
   Once all limits created by this API are released, the original CPU resource
   limits are restored (if any). This uses setrlimit() with RLIMIT_CPU
   internally, which counts both user and system CPU time.
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
