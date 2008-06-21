#ifndef MASTER_LOGIN_INTERFACE_H
#define MASTER_LOGIN_INTERFACE_H

#include "network.h"

#define LOGIN_MASTER_SOCKET_FD 3

/* Increase the version number every time master_login_request
   (or something else) is changed. */
#define MASTER_LOGIN_PROTOCOL_VERSION 3

/* This should be kept in sync with LOGIN_MAX_INBUF_SIZE. Multiply it by two
   to make sure there's space to transfer the command tag  */
#define MASTER_LOGIN_MAX_DATA_SIZE (4096*2)

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

enum master_login_flags {
	LOGIN_IMAP_FLAG_FULL_CAPABILITY_SENT	= 0x01
};

struct master_login_request {
	uint32_t version;
	/* if fd == -1, tag is used as master_login_state */
	uint32_t tag;

	uint32_t auth_pid;
	uint32_t auth_id;
	/* request follows this many bytes of client input */
	uint16_t data_size;
	uint16_t cmd_tag_size;
	uint32_t flags;

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
