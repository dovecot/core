#ifndef ENV_UTIL_H
#define ENV_UTIL_H

/* Add new environment variable. Wrapper to putenv(). Note that calls to this
   function allocates memory which isn't free'd until env_clean() is called. */
void env_put(const char *env);
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

/* Free all memory used by env_put() function. Environment must not be
   accessed afterwards. */
void env_deinit(void);

#endif
