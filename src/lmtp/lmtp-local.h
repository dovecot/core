#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

#include "net.h"

struct mail_deliver_session;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct lmtp_local;
struct client;

void lmtp_local_deinit(struct lmtp_local **_local);

int lmtp_local_rcpt(struct client *client,
		    struct smtp_server_cmd_ctx *cmd,
		    struct lmtp_recipient *lrcpt, const char *username,
		    const char *detail);

void lmtp_local_add_headers(struct lmtp_local *local,
			    struct smtp_server_transaction *trans,
			    string_t *headers);

int lmtp_local_default_deliver(struct client *client,
			       struct lmtp_recipient *lrcpt,
			       struct smtp_server_cmd_ctx *cmd,
			       struct smtp_server_transaction *trans,
			       struct lmtp_local_deliver_context *lldctx);

void lmtp_local_data(struct client *client,
		     struct smtp_server_cmd_ctx *cmd,
		     struct smtp_server_transaction *trans,
		     struct istream *input);

#endif
