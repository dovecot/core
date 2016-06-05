#ifndef IMAP_LOGIN_CLIENT_H
#define IMAP_LOGIN_CLIENT_H

#include "net.h"
#include "imap-id.h"
#include "client-common.h"

/* Master prefix is: <1|0><imap tag><NUL> */
#define IMAP_TAG_MAX_LEN (LOGIN_MAX_MASTER_PREFIX_LEN-2)

enum imap_client_id_state {
	IMAP_CLIENT_ID_STATE_LIST = 0,
	IMAP_CLIENT_ID_STATE_KEY,
	IMAP_CLIENT_ID_STATE_VALUE
};

struct imap_client_cmd_id {
	struct imap_parser *parser;

	enum imap_client_id_state state;
	char key[IMAP_ID_KEY_MAX_LEN+1];

	char **log_keys;
	string_t *log_reply;
};

struct imap_client {
	struct client common;

	const struct imap_login_settings *set;
	struct imap_parser *parser;
	char *proxy_backend_capability;

	const char *cmd_tag, *cmd_name;
	struct imap_client_cmd_id *cmd_id;

	bool cmd_finished:1;
	bool proxy_sasl_ir:1;
	bool proxy_logindisabled:1;
	bool proxy_seen_banner:1;
	bool skip_line:1;
	bool id_logged:1;
	bool proxy_capability_request_sent:1;
	bool client_ignores_capability_resp_code:1;
	bool auth_mech_name_parsed:1;
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
