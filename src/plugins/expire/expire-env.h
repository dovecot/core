#ifndef EXPIRE_ENV_H
#define EXPIRE_ENV_H

struct expire_env;

struct expire_box {
	const char *name;
	time_t expire_secs;
};

struct expire_env *expire_env_init(const char *str);
void expire_env_deinit(struct expire_env *env);

const struct expire_box *expire_box_find(struct expire_env *env,
					 const char *name);

#endif
