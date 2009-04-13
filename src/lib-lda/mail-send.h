#ifndef MAIL_SEND_H
#define MAIL_SEND_H

struct mail;
struct mail_deliver_context;

int mail_send_rejection(struct mail_deliver_context *ctx, const char *recipient,
			const char *reason);
int mail_send_forward(struct mail_deliver_context *ctx, const char *forwardto);

#endif
