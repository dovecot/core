#ifndef MASTER_AUTH_H
#define MASTER_AUTH_H

#include "network.h"

struct master_service;

/* Major version changes are not backwards compatible,
   minor version numbers can be ignored. */
#define AUTH_MASTER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_MASTER_PROTOCOL_MINOR_VERSION 1

/* Authentication client process's cookie size */
#define MASTER_AUTH_COOKIE_SIZE (128/8)

/* This should be kept in sync with LOGIN_MAX_INBUF_SIZE. Multiply it by two
   to make sure there's space to transfer the command tag  */
#define MASTER_AUTH_MAX_DATA_SIZE (1024*2)

#define MASTER_AUTH_ERRMSG_INTERNAL_FAILURE \
	"Internal error occurred. Refer to server log for more information."

enum mail_auth_request_flags {
	/* Connection has TLS compression enabled */
	MAIL_AUTH_REQUEST_FLAG_TLS_COMPRESSION	= 0x01
};

/* Authentication request. File descriptor may be sent along with the
   request. */
struct master_auth_request {
	/* Request tag. Reply is sent back using same tag. */
	unsigned int tag;

	/* Authentication process, authentication ID and auth cookie. */
	pid_t auth_pid;
	unsigned int auth_id;
	unsigned int client_pid;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];

	/* Local and remote IPs of the connection. The file descriptor
	   itself may be a local socketpair. */
	struct ip_addr local_ip, remote_ip;

	uint32_t flags;

	/* request follows this many bytes of client input */
	uint32_t data_size;
	/* inode of the transferred fd. verified just to be sure that the
	   correct fd is mapped to the correct struct. */
	ino_t ino;
};

enum master_auth_status {
	MASTER_AUTH_STATUS_OK,
	MASTER_AUTH_STATUS_INTERNAL_ERROR
};

struct master_auth_reply {
	/* tag=0 are notifications from master */
	unsigned int tag;
	enum master_auth_status status;
	/* PID of the post-login mail process handling this connection */
	pid_t mail_pid;
};

/* reply=NULL if the auth lookup was cancelled due to some error */
typedef void master_auth_callback_t(const struct master_auth_reply *reply,
				    void *context);

struct master_auth *
master_auth_init(struct master_service *service, const char *path);
void master_auth_deinit(struct master_auth **auth);

/* Send an authentication request. The fd contains the file descriptor to
   transfer, or -1 if no fd is wanted to be transferred. Returns tag which can
   be used to abort the request (ie. ignore the reply from master).
   request->tag is ignored. */
void master_auth_request(struct master_auth *auth, int fd,
			 const struct master_auth_request *request,
			 const unsigned char *data,
			 master_auth_callback_t *callback,
			 void *context, unsigned int *tag_r);
void master_auth_request_abort(struct master_auth *auth, unsigned int tag);

#endif
