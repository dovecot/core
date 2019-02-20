#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "client-common.h"
#include "auth-client.h"
#include "smtp-server.h"

enum submission_proxy_state {
	SUBMISSION_PROXY_BANNER = 0,
	SUBMISSION_PROXY_EHLO,
	SUBMISSION_PROXY_STARTTLS,
	SUBMISSION_PROXY_TLS_EHLO,
	SUBMISSION_PROXY_XCLIENT,
	SUBMISSION_PROXY_AUTHENTICATE,

	SUBMISSION_PROXY_STATE_COUNT
};

struct submission_client {
	struct client common;
	const struct submission_login_settings *set;
	enum smtp_capability backend_capabilities;

	struct smtp_server_connection *conn;
	struct smtp_server_cmd_ctx *pending_auth, *pending_starttls;

	enum submission_proxy_state proxy_state;
	enum smtp_capability proxy_capability;
	unsigned int proxy_reply_status;
	struct smtp_server_reply *proxy_reply;
	const char **proxy_xclient;
};

#endif
