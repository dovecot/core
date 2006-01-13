#ifndef __MASTER_LOGIN_INTERFACE_H
#define __MASTER_LOGIN_INTERFACE_H

#include "network.h"

#define LOGIN_LISTEN_FD 0
#define LOGIN_SSL_LISTEN_FD 1
#define LOGIN_MASTER_SOCKET_FD 3

/* Increase the version number every time master_login_request
   (or something else) is changed. */
#define MASTER_LOGIN_PROTOCOL_VERSION 1

struct master_login_request {
	uint32_t version;
	uint32_t tag;

	uint32_t auth_pid;
	uint32_t auth_id;

	struct ip_addr local_ip, remote_ip;
};

struct master_login_reply {
	unsigned int tag;
	bool success;
};

#endif
