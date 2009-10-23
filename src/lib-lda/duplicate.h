#ifndef DUPLICATE_H
#define DUPLICATE_H

struct duplicate_context;
struct mail_storage_settings;

#define DUPLICATE_DEFAULT_KEEP (3600 * 24)

int duplicate_check(struct duplicate_context *ctx,
		    const void *id, size_t id_size, const char *user);
void duplicate_mark(struct duplicate_context *ctx,
		    const void *id, size_t id_size,
                    const char *user, time_t timestamp);

void duplicate_flush(struct duplicate_context *ctx);

struct duplicate_context *duplicate_init(struct mail_user *user);
void duplicate_deinit(struct duplicate_context **ctx);

#endif
