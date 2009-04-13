#ifndef DUPLICATE_H
#define DUPLICATE_H

struct mail_storage_settings;

#define DUPLICATE_DEFAULT_KEEP (3600 * 24)

int duplicate_check(const void *id, size_t id_size, const char *user);
void duplicate_mark(const void *id, size_t id_size,
                    const char *user, time_t timestamp);

void duplicate_flush(void);

void duplicate_init(const struct mail_storage_settings *set);
void duplicate_deinit(void);

#endif
