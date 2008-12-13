#ifndef ENV_UTIL_H
#define ENV_UTIL_H

/* Add new environment variable. Wrapper to putenv(). Note that calls to this
   function allocates memory which isn't free'd until env_clean() is called. */
void env_put(const char *env);
/* Remove a single environment. */
void env_remove(const char *name);
/* Clear all environment variables. */
void env_clean(void);

#endif
