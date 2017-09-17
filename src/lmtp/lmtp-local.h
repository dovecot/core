#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct client;
struct mail_recipient;

void client_rcpt_anvil_disconnect(const struct mail_recipient *rcpt);

void client_send_line_overquota(struct client *client,
			   const struct mail_recipient *rcpt, const char *error);

bool cmd_rcpt_finish(struct client *client, struct mail_recipient *rcpt);

void rcpt_anvil_lookup_callback(const char *reply, void *context);

#endif
