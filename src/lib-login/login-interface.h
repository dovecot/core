#ifndef LOGIN_INTERFACE_H
#define LOGIN_INTERFACE_H

#include "net.h"

/* Authentication client process's cookie size */
#define LOGIN_REQUEST_COOKIE_SIZE (128/8)

/* LOGIN_MAX_INBUF_SIZE should be based on this. Keep this large enough so that
   LOGIN_MAX_INBUF_SIZE will be 1024+2 bytes. This is because IMAP ID command's
   values may be max. 1024 bytes plus 2 for "" quotes. (Although it could be
   even double of that when value is full of \" quotes, but for now lets not
   make it too easy to waste memory..) */
#define LOGIN_REQUEST_MAX_DATA_SIZE (1024 + 128 + 64 + 2)

#define LOGIN_REQUEST_ERRMSG_INTERNAL_FAILURE \
	"Internal error occurred. Refer to server log for more information."

enum login_request_flags {
	/* Connection has TLS compression enabled */
	LOGIN_REQUEST_FLAG_TLS_COMPRESSION	= BIT(0),
	/* The end client connection (not just the previous hop proxy
	   connection) is using TLS. */
	LOGIN_REQUEST_FLAG_END_CLIENT_SECURED_TLS = BIT(2),
	/* This login is implicit; no command reply is expected */
	LOGIN_REQUEST_FLAG_IMPLICIT		= BIT(3),
};

/* Login request. File descriptor may be sent along with the request. */
struct login_request {
	/* Request tag. Reply is sent back using same tag. */
	unsigned int tag;

	/* Authentication process, authentication ID and auth cookie. */
	pid_t auth_pid;
	unsigned int auth_id;
	unsigned int client_pid;
	uint8_t cookie[LOGIN_REQUEST_COOKIE_SIZE];

	/* Properties of the connection. The file descriptor
	   itself may be a local socketpair. */
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;

	uint32_t flags;

	/* request follows this many bytes of client input */
	uint32_t data_size;
	/* inode of the transferred fd. verified just to be sure that the
	   correct fd is mapped to the correct struct. */
	ino_t ino;
};

enum login_reply_status {
	LOGIN_REPLY_STATUS_OK,
	LOGIN_REPLY_STATUS_INTERNAL_ERROR
};

struct login_reply {
	/* tag=0 are notifications from master */
	unsigned int tag;
	enum login_reply_status status;
	/* PID of the post-login mail process handling this connection */
	pid_t mail_pid;
};

#endif
