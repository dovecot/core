#ifndef MAIL_SEND_H
#define MAIL_SEND_H

struct mail;

int mail_send_rejection(struct mail *mail, const char *recipient,
			const char *reason);
int mail_send_forward(struct mail *mail, const char *forwardto);

#endif
