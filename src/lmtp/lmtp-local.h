#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct smtp_address;
struct client;
struct lmtp_recipient;
struct mail_deliver_session;

void lmtp_local_rcpt_deinit(struct lmtp_recipient *rcpt);

int lmtp_local_rcpt(struct client *client,
	struct lmtp_recipient *rcpt,
	struct smtp_address *address,
	const char *username, const char *detail);

void lmtp_local_data(struct client *client, struct istream *input);

#endif
