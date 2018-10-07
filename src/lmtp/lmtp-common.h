#ifndef LMTP_COMMON_H
#define LMTP_COMMON_H

struct smtp_address;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct smtp_server_recipient;
struct client;

enum lmtp_recipient_type {
	LMTP_RECIPIENT_TYPE_LOCAL,
	LMTP_RECIPIENT_TYPE_PROXY,
};

struct lmtp_recipient {
	struct client *client;
	enum lmtp_recipient_type type;

	struct smtp_address *path;
	struct smtp_server_cmd_ctx *rcpt_cmd;
	struct smtp_server_recipient *rcpt;
	unsigned int index;
};

void lmtp_recipient_init(struct lmtp_recipient *lrcpt,
			 struct client *client,
			 enum lmtp_recipient_type type,
			 struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_recipient *rcpt);

void lmtp_recipient_finish(struct lmtp_recipient *lrcpt);

struct lmtp_recipient *
lmtp_recipient_find_duplicate(struct lmtp_recipient *lrcpt,
			      struct smtp_server_transaction *trans);

#endif
