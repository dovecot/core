#ifndef MASTER_AUTH_H
#define MASTER_AUTH_H

#include "net.h"

struct master_service;

/* Major version changes are not backwards compatible,
   minor version numbers can be ignored. */
#define AUTH_MASTER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_MASTER_PROTOCOL_MINOR_VERSION 1

/* Authentication client process's cookie size */
#define MASTER_AUTH_COOKIE_SIZE (128/8)

/* LOGIN_MAX_INBUF_SIZE should be based on this. Keep this large enough so that
   LOGIN_MAX_INBUF_SIZE will be 1024+2 bytes. This is because IMAP ID command's
   values may be max. 1024 bytes plus 2 for "" quotes. (Although it could be
   even double of that when value is full of \" quotes, but for now lets not
   make it too easy to waste memory..) */
#define MASTER_AUTH_MAX_DATA_SIZE (1024 + 128 + 64 + 2)

#define MASTER_AUTH_ERRMSG_INTERNAL_FAILURE \
	"Internal error occurred. Refer to server log for more information."

enum mail_auth_request_flags {
	/* Connection has TLS compression enabled */
	MAIL_AUTH_REQUEST_FLAG_TLS_COMPRESSION	= BIT(0),
	/* Connection is secure (SSL or just trusted) */
	MAIL_AUTH_REQUEST_FLAG_CONN_SECURED = BIT(1),
	/* Connection is secured using SSL specifically */
	MAIL_AUTH_REQUEST_FLAG_CONN_SSL_SECURED = BIT(2),
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

struct master_auth_request_params {
	/* Client fd to transfer to post-login process or -1 if no fd is
	   wanted to be transferred. */
	int client_fd;
	/* Override master_auth->default_path if non-NULL */
	const char *socket_path;

	/* Authentication request that is sent to post-login process.
	   tag is ignored. */
	struct master_auth_request request;
	/* Client input of size request.data_size */
	const unsigned char *data;
};

/* reply=NULL if the auth lookup was cancelled due to some error */
typedef void master_auth_callback_t(const struct master_auth_reply *reply,
				    void *context);

struct master_auth *
master_auth_init(struct master_service *service, const char *path);
void master_auth_deinit(struct master_auth **auth);

/* Send an authentication request. Returns tag which can be used to abort the
   request (ie. ignore the reply from master). */
void master_auth_request_full(struct master_auth *auth,
			      const struct master_auth_request_params *params,
			      master_auth_callback_t *callback, void *context,
			      unsigned int *tag_r);
/* For backwards compatibility: */
void master_auth_request(struct master_auth *auth, int fd,
			 const struct master_auth_request *request,
			 const unsigned char *data,
			 master_auth_callback_t *callback,
			 void *context, unsigned int *tag_r);
void master_auth_request_abort(struct master_auth *auth, unsigned int tag);

#endif
