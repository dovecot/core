#ifndef MASTER_INTERFACE_H
#define MASTER_INTERFACE_H

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

enum master_login_state {
	MASTER_LOGIN_STATE_NONFULL = 0,
	MASTER_LOGIN_STATE_FULL
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

/* Write pipe to anvil. */
#define MASTER_ANVIL_FD 3
/* Anvil reads new log fds from this fd */
#define MASTER_ANVIL_LOG_FDPASS_FD 4
/* Master's "all processes full" notification fd for login processes */
#define MASTER_LOGIN_NOTIFY_FD 4

/* Shared pipe to master, used to send master_status reports */
#define MASTER_STATUS_FD 5
/* First file descriptor where process is expected to be listening.
   The file descriptor count is given in -s parameter, defaulting to 1.

   master_status.available_count reports how many accept()s we're still
   accepting. Once no children are listening, master will do it and create
   new child processes when needed. */
#define MASTER_LISTEN_FD_FIRST 6

#endif
