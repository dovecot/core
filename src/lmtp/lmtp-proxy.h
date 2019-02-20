#ifndef LMTP_PROXY_H
#define LMTP_PROXY_H

#include "net.h"

#include "smtp-common.h"
#include "smtp-params.h"
#include "smtp-client.h"

#define LMTP_PROXY_DEFAULT_TTL 5

struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct lmtp_proxy;
struct client;

void lmtp_proxy_deinit(struct lmtp_proxy **proxy);

int lmtp_proxy_rcpt(struct client *client,
		    struct smtp_server_cmd_ctx *cmd,
		    struct lmtp_recipient *rcpt, const char *username,
		    const char *detail, char delim);

void lmtp_proxy_data(struct client *client,
		     struct smtp_server_cmd_ctx *cmd,
		     struct smtp_server_transaction *trans ATTR_UNUSED,
		     struct istream *data_input);

#endif
