#ifndef __MASTER_LOGIN_INTERFACE_H
#define __MASTER_LOGIN_INTERFACE_H

#include "network.h"

#define LOGIN_MASTER_SOCKET_FD 3

/* Increase the version number every time master_login_request
   (or something else) is changed. */
#define MASTER_LOGIN_PROTOCOL_VERSION 3

enum master_login_state {
	/* process is accepting new connections */
	LOGIN_STATE_LISTENING = 0,
	/* process isn't accepting new connections, but it'd be able to kill
	   some connections which haven't logged in yet */
	LOGIN_STATE_FULL_PRELOGINS,
	/* process is handling only logged in users */
	LOGIN_STATE_FULL_LOGINS,

	LOGIN_STATE_COUNT
};

struct master_login_request {
	uint32_t version;
	/* if fd == -1, tag is used as master_login_state */
	uint32_t tag;

	uint32_t auth_pid;
	uint32_t auth_id;

	ino_t ino;

	struct ip_addr local_ip, remote_ip;
};

enum master_login_status {
	MASTER_LOGIN_STATUS_OK,
	MASTER_LOGIN_STATUS_INTERNAL_ERROR,
	/* user reached max. simultaneous connections */
	MASTER_LOGIN_STATUS_MAX_CONNECTIONS
};

struct master_login_reply {
	unsigned int tag;
	enum master_login_status status;
};

#endif
