#ifndef MAIL_SEND_H
#define MAIL_SEND_H

struct mail;
struct mail_deliver_context;

int mail_send_rejection(struct mail_deliver_context *ctx,
			const struct smtp_address *recipient,
			const char *reason);

#endif
