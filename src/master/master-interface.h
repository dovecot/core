#ifndef __MASTER_INTERFACE_H
#define __MASTER_INTERFACE_H

#include "network.h"
#include "../auth/auth-interface.h"

#define LOGIN_TAG_SIZE 32

#define LOGIN_MASTER_SOCKET_FD 0
#define LOGIN_IMAP_LISTEN_FD 1
#define LOGIN_IMAPS_LISTEN_FD 2

typedef enum {
	MASTER_RESULT_INTERNAL_FAILURE,
	MASTER_RESULT_SUCCESS,
	MASTER_RESULT_FAILURE
} MasterReplyResult;

typedef struct {
	unsigned int id;

	unsigned int auth_process;
	unsigned char cookie[AUTH_COOKIE_SIZE];

	IPADDR ip;
	char login_tag[LOGIN_TAG_SIZE];
} MasterRequest;

typedef struct {
	unsigned int id;
        MasterReplyResult result;
} MasterReply;

#endif
