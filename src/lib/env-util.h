#ifndef ENV_UTIL_H
#define ENV_UTIL_H

/* Add a new environment variable or replace an existing one.
   Wrapper to setenv(). Note that setenv() often doesn't free memory used by
   replaced environment, so don't keep repeatedly changing values in
   environment. */
void env_put(const char *name, const char *value);
/* env_put() NULL-terminated array of name=value strings */
void env_put_array(const char *const *envs);
/* Remove a single environment. */
void env_remove(const char *name);
/* Clear all environment variables. */
void env_clean(void);
/* Clear all environment variables except what's listed in preserve_envs[] */
void env_clean_except(const char *const preserve_envs[]);

/* Save a copy of the current environment. */
struct env_backup *env_backup_save(void);
/* Clear the current environment and restore the backup. */
void env_backup_restore(struct env_backup *env);
/* Free the memory used by environment backup. */
void env_backup_free(struct env_backup **env);

/* Returns the value of "&environ". This is more portable than using it
   directly. */
char ***env_get_environ_p(void);


#endif
