#ifndef MASTER_INTERFACE_H
#define MASTER_INTERFACE_H

#include "network.h"

/* We are attempting semi-compatibility with Postfix's master process here.
   Whether this is useful or not remains to be seen. */

/* Child processes should send status updates whenever they accept a new
   connection (decrease available_count) and when they close existing
   connection (increase available_count). */
struct master_status {
	pid_t pid;
	/* uid is used to check for old/invalid status messages */
	unsigned int uid;
	/* number of new connections process is currently accepting */
	unsigned int available_count;
};

/* When connecting to log service, send this handshake first */
struct log_service_handshake {
	/* If magic is invalid, assume the data is already what we want
	   to log */
#define MASTER_LOG_MAGIC 0x02ff03fe
	unsigned int log_magic;

	/* Add this prefix to each logged line */
#define MASTER_LOG_PREFIX_NAME "MASTER"
	unsigned int prefix_len;
	/* unsigned char prefix[]; */
};

/* This should be kept in sync with LOGIN_MAX_INBUF_SIZE. Multiply it by two
   to make sure there's space to transfer the command tag  */
#define MASTER_AUTH_MAX_DATA_SIZE (1024*2)

/* Authentication client process's cookie size */
#define MASTER_AUTH_COOKIE_SIZE (128/8)

/* Authentication request. File descriptor may be sent along with the
   request. */
struct master_auth_request {
	/* Request tag. Reply is sent back using same tag. */
	unsigned int tag;

	/* Authentication process, authentication ID and auth cookie. */
	pid_t auth_pid;
	unsigned int auth_id;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];

	/* Local and remote IPs of the connection. The file descriptor
	   itself may be a local socketpair. */
	struct ip_addr local_ip, remote_ip;

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

/* getenv(MASTER_UID_ENV) provides master_status.uid value */
#define MASTER_UID_ENV "GENERATION"

/* getenv(MASTER_CLIENT_LIMIT_ENV) provides maximum
   master_status.available_count as specified in configuration file */
#define MASTER_CLIENT_LIMIT_ENV "CLIENT_LIMIT"

/* getenv(MASTER_SERVICE_COUNT_ENV) specifies how many client connections the
   process can finish handling before it should kill itself. */
#define MASTER_SERVICE_COUNT_ENV "SERVICE_COUNT"

/* getenv(MASTER_CONFIG_FILE_ENV) provides path to configuration file/socket */
#define MASTER_CONFIG_FILE_ENV "CONFIG_FILE"

/* getenv(MASTER_DOVECOT_VERSION_ENV) provides master's version number */
#define MASTER_DOVECOT_VERSION_ENV "DOVECOT_VERSION"

/* getenv(MASTER_SSL_KEY_PASSWORD_ENV) returns manually typed SSL key password,
   if dovecot was started with -p parameter. */
#define MASTER_SSL_KEY_PASSWORD_ENV "SSL_KEY_PASSWORD"

/* Write pipe to anvil. Currently available only for auth destination
   services, for others it's /dev/null. */
#define MASTER_ANVIL_FD 3

/* Socket for sending master_auth_requests. Also used by auth server process
   as a master socket. */
#define MASTER_AUTH_FD 4

/* Shared pipe to master, used to send master_status reports */
#define MASTER_STATUS_FD 5
/* First file descriptor where process is expected to be listening.
   The file descriptor count is given in -s parameter, defaulting to 1.

   master_status.available_count reports how many accept()s we're still
   accepting. Once no children are listening, master will do it and create
   new child processes when needed. */
#define MASTER_LISTEN_FD_FIRST 6

#endif
