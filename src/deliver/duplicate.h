#ifndef DUPLICATE_H
#define DUPLICATE_H

#define DUPLICATE_DEFAULT_KEEP (3600 * 24)

int duplicate_check(const void *id, size_t id_size, const char *user);
void duplicate_mark(const void *id, size_t id_size,
                    const char *user, time_t time);

void duplicate_flush(void);

void duplicate_init(void);
void duplicate_deinit(void);

#endif
