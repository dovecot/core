#ifndef EXPIRE_ENV_H
#define EXPIRE_ENV_H

struct expire_env;

struct expire_env *expire_env_init(const char *expunges, const char *altmoves);
void expire_env_deinit(struct expire_env *env);

bool expire_box_find(struct expire_env *env, const char *name,
		     unsigned int *expunge_secs_r,
		     unsigned int *altmove_secs_r);

unsigned int expire_box_find_min_secs(struct expire_env *env, const char *name,
				      bool *altmove_r);

#endif
