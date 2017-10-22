#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct smtp_address;
struct smtp_params_rcpt;
struct lmtp_recipient;
struct lmtp_local;
struct client;

unsigned int lmtp_local_rcpt_count(struct client *client);

void lmtp_local_deinit(struct lmtp_local **_local);

int lmtp_local_rcpt(struct client *client,
	struct smtp_address *address,
	const char *username, const char *detail,
	const struct smtp_params_rcpt *params);

void lmtp_local_add_headers(struct lmtp_local *local,
			    string_t *headers);

void lmtp_local_data(struct client *client, struct istream *input);

#endif
