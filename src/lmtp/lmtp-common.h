#ifndef LMTP_COMMON_H
#define LMTP_COMMON_H

struct smtp_address;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct smtp_server_recipient;
struct client;

struct lmtp_recipient {
	struct client *client;

	struct smtp_address *path;
	struct smtp_server_cmd_ctx *rcpt_cmd;
	struct smtp_server_recipient *rcpt;
	unsigned int index;
};

void lmtp_recipient_init(struct lmtp_recipient *rcpt,
			 struct client *client,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_cmd_rcpt *data);

void lmtp_recipient_finish(struct lmtp_recipient *rcpt,
			   struct smtp_server_recipient *trcpt,
			   unsigned int index);

#endif
