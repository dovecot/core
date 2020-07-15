#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "client-common.h"
#include "auth-client.h"

enum pop3_proxy_state {
	POP3_PROXY_BANNER = 0,
	POP3_PROXY_STARTTLS,
	POP3_PROXY_XCLIENT,
	POP3_PROXY_LOGIN1,
	POP3_PROXY_LOGIN2,

	POP3_PROXY_STATE_COUNT
};

struct pop3_client {
	struct client common;

	char *current_cmd;
	char *last_user;
	char *apop_challenge;
	unsigned int apop_server_pid, apop_connect_uid;
	enum pop3_proxy_state proxy_state;
	bool proxy_xclient;
	bool auth_mech_name_parsed;
};

enum pop3_cmd_reply {
	POP3_CMD_REPLY_OK,
	POP3_CMD_REPLY_ERROR,
	POP3_CMD_REPLY_AUTH_ERROR,
	POP3_CMD_REPLY_TEMPFAIL
};

void client_send_reply(struct client *client, enum pop3_cmd_reply reply,
		       const char *text);

#endif
