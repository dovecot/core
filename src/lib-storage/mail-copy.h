#ifndef MAIL_COPY_H
#define MAIL_COPY_H

struct mail;
struct mail_save_context;

int mail_storage_copy(struct mail_save_context *ctx, struct mail *mail);

#endif
