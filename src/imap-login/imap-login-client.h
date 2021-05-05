#ifndef IMAP_LOGIN_CLIENT_H
#define IMAP_LOGIN_CLIENT_H

#include "net.h"
#include "imap-id.h"
#include "client-common.h"

/* Master prefix is: <1|0><imap tag><NUL> */
#define IMAP_TAG_MAX_LEN (LOGIN_MAX_MASTER_PREFIX_LEN-2)

/* maximum length for IMAP command line. */
#define IMAP_LOGIN_MAX_LINE_LENGTH 8192

enum imap_client_id_state {
	IMAP_CLIENT_ID_STATE_LIST = 0,
	IMAP_CLIENT_ID_STATE_KEY,
	IMAP_CLIENT_ID_STATE_VALUE
};

/* Multiple commands can be sent pipelined, so the sent_state is a bitmask */
enum imap_proxy_sent_state {
	IMAP_PROXY_SENT_STATE_ID		= 0x01,
	IMAP_PROXY_SENT_STATE_STARTTLS		= 0x02,
	IMAP_PROXY_SENT_STATE_CAPABILITY	= 0x04,
	IMAP_PROXY_SENT_STATE_AUTHENTICATE	= 0x08,
	IMAP_PROXY_SENT_STATE_AUTH_CONTINUE	= 0x10,
	IMAP_PROXY_SENT_STATE_LOGIN		= 0x20,

	IMAP_PROXY_SENT_STATE_COUNT = 6
};

enum imap_proxy_rcvd_state {
	IMAP_PROXY_RCVD_STATE_NONE,
	IMAP_PROXY_RCVD_STATE_BANNER,
	IMAP_PROXY_RCVD_STATE_ID,
	IMAP_PROXY_RCVD_STATE_STARTTLS,
	IMAP_PROXY_RCVD_STATE_CAPABILITY,
	IMAP_PROXY_RCVD_STATE_AUTH_CONTINUE,
	IMAP_PROXY_RCVD_STATE_LOGIN,

	IMAP_PROXY_RCVD_STATE_COUNT
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
	struct imap_capability_list *capability_list;
	char *proxy_backend_capability;

	const char *cmd_tag, *cmd_name;
	struct imap_client_cmd_id *cmd_id;

	enum imap_proxy_sent_state proxy_sent_state;
	enum imap_proxy_rcvd_state proxy_rcvd_state;

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
bool client_handle_parser_error(struct imap_client *client,
				struct imap_parser *parser);

int cmd_id(struct imap_client *client);

#endif
