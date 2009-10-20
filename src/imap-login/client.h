#ifndef CLIENT_H
#define CLIENT_H

#include "network.h"
#include "client-common.h"

struct imap_client {
	struct client common;

	const struct imap_login_settings *set;
	struct imap_parser *parser;
	char *proxy_backend_capability;

	const char *cmd_tag, *cmd_name;

	unsigned int cmd_finished:1;
	unsigned int proxy_sasl_ir:1;
	unsigned int proxy_seen_banner:1;
	unsigned int proxy_wait_auth_continue:1;
	unsigned int skip_line:1;
	unsigned int id_logged:1;
	unsigned int client_ignores_capability_resp_code:1;
};

bool client_skip_line(struct imap_client *client);

#endif
