#ifndef PENALTY_H
#define PENALTY_H

#define PENALTY_MAX_VALUE ((1 << 16)-1)

struct penalty *penalty_init(void);
void penalty_deinit(struct penalty **penalty);

void penalty_set_expire_secs(struct penalty *penalty, unsigned int expire_secs);

unsigned int penalty_get(struct penalty *penalty, const char *ident,
			 time_t *last_penalty_r);
/* if checksum is non-zero and it already exists for ident, the value
   is set to "value-1", otherwise it's set to "value". */
void penalty_inc(struct penalty *penalty, const char *ident,
		 unsigned int checksum, unsigned int value);

bool penalty_has_checksum(struct penalty *penalty, const char *ident,
			  unsigned int checksum);
void penalty_dump(struct penalty *penalty, struct ostream *output);

#endif
