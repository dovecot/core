#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "client-common.h"

/* Master prefix is: <1|0><imap tag><NUL> */
#define IMAP_TAG_MAX_LEN (LOGIN_MAX_MASTER_PREFIX_LEN-2)

struct imap_client {
	struct client common;

	const struct imap_login_settings *set;
	struct imap_parser *parser;
	char *proxy_backend_capability;

	const char *cmd_tag, *cmd_name;

	unsigned int cmd_finished:1;
	unsigned int proxy_sasl_ir:1;
	unsigned int proxy_seen_banner:1;
	unsigned int skip_line:1;
	unsigned int id_logged:1;
	unsigned int client_ignores_capability_resp_code:1;
	unsigned int auth_mech_name_parsed:1;
};

bool client_skip_line(struct imap_client *client);

enum imap_cmd_reply {
	IMAP_CMD_REPLY_OK,
	IMAP_CMD_REPLY_NO,
	IMAP_CMD_REPLY_BAD,
	IMAP_CMD_REPLY_BYE
};

void client_send_reply(struct client *client,
		       enum imap_cmd_reply reply, const char *text);

void client_send_reply_code(struct client *client,
			    enum imap_cmd_reply reply, const char *resp_code,
			    const char *text) ATTR_NULL(3);

#endif
