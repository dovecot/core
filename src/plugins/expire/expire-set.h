#ifndef EXPIRE_SET_H
#define EXPIRE_SET_H

#define DICT_EXPIRE_PREFIX DICT_PATH_SHARED"expire/"

struct expire_set *expire_set_init(const char *const *patterns);
void expire_set_deinit(struct expire_set **set);

bool expire_set_lookup(struct expire_set *set, const char *mailbox);

#endif
