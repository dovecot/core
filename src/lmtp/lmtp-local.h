#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct client;
struct mail_recipient;
struct mail_deliver_session;

void client_rcpt_anvil_disconnect(const struct mail_recipient *rcpt);

bool cmd_rcpt_finish(struct client *client, struct mail_recipient *rcpt);

void rcpt_anvil_lookup_callback(const char *reply, void *context);

uid_t client_deliver_to_rcpts(struct client *client,
				    struct mail_deliver_session *session);

#endif
