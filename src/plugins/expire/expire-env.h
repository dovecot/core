#ifndef EXPIRE_ENV_H
#define EXPIRE_ENV_H

#define DICT_EXPIRE_PREFIX DICT_PATH_SHARED"expire/"

struct expire_env;
struct mail_namespace;

struct expire_env *expire_env_init(struct mail_namespace *namespaces);
void expire_env_deinit(struct expire_env **env);

bool expire_rule_find(struct expire_env *env, const char *name,
		      unsigned int *expunge_secs_r,
		      unsigned int *altmove_secs_r);

unsigned int expire_rule_find_min_secs(struct expire_env *env, const char *name,
				       bool *altmove_r);

#endif
