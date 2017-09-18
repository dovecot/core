#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct client;
struct lmtp_recipient;
struct mail_deliver_session;

void lmtp_local_rcpt_anvil_disconnect(const struct lmtp_recipient *rcpt);

bool cmd_rcpt_finish(struct client *client, struct lmtp_recipient *rcpt);

void rcpt_anvil_lookup_callback(const char *reply, void *context);

void lmtp_local_data(struct client *client, struct istream *input);

#endif
