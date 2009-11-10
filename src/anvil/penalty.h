#ifndef PENALTY_H
#define PENALTY_H

struct penalty *penalty_init(void);
void penalty_deinit(struct penalty **penalty);

void penalty_set_expire_secs(struct penalty *penalty, unsigned int expire_secs);

unsigned int penalty_get(struct penalty *penalty, const char *ident,
			 time_t *last_update_r);
void penalty_set(struct penalty *penalty, const char *ident,
		 unsigned int value);

#endif
