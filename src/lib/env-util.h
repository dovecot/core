#ifndef ENV_UTIL_H
#define ENV_UTIL_H

/* Add new environment variable. Wrapper to putenv(). Note that calls to this
   function allocates memory which isn't free'd until env_clean() is called. */
void env_put(const char *env);
/* Clear all environment variables. */
void env_clean(void);

/* Append a string containing key=value to the array */
void envarr_add(ARRAY_TYPE(const_string) *arr,
		const char *key, const char *value);
void envarr_addi(ARRAY_TYPE(const_string) *arr, const char *key,
		 unsigned int value);
/* Append a string containing key=1 to the array */
void envarr_addb(ARRAY_TYPE(const_string) *arr, const char *key);

#endif
