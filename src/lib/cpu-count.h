#ifndef CPU_COUNT_H
#define CPU_COUNT_H

/* Determines number of CPUs in the system and places it in
 * cpu_count_r. On success 0 is returned, on failure, -1
 * is returned and error placed in error_r. */
int cpu_count_get(int *cpu_count_r, const char **error_r);

#endif
