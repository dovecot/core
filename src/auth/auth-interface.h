#ifndef __AUTH_INTERFACE_H
#define __AUTH_INTERFACE_H

#define AUTH_COOKIE_SIZE		16

#define AUTH_MAX_REQUEST_DATA_SIZE	4096
#define AUTH_MAX_REPLY_DATA_SIZE	4096

#define AUTH_MAX_USER_LEN		64
#define AUTH_MAX_VUSER_LEN		256
#define AUTH_MAX_HOME_LEN		256
#define AUTH_MAX_MAIL_LEN		256

enum auth_request_type {
	AUTH_REQUEST_NONE, /* must not be requested */
	AUTH_REQUEST_INIT,
        AUTH_REQUEST_CONTINUE
};

enum auth_result {
	AUTH_RESULT_INTERNAL_FAILURE, /* never sent by imap-auth */

	AUTH_RESULT_CONTINUE,
	AUTH_RESULT_SUCCESS,
	AUTH_RESULT_FAILURE
};

enum auth_mech {
	AUTH_MECH_PLAIN		= 0x01,
	AUTH_MECH_DIGEST_MD5	= 0x02,

	AUTH_MECH_COUNT		= 2
};

/* Initialization reply, sent after client is connected */
struct auth_init_data {
	unsigned int auth_process; /* unique auth process identifier */
	enum auth_mech auth_mechanisms; /* valid authentication mechanisms */
};

/* Initialization handshake from client. */
struct client_auth_init_data {
	unsigned int pid; /* unique identifier for client process */
};

/* New authentication request */
struct auth_init_request_data {
	enum auth_request_type type; /* AUTH_REQUEST_INIT */

	enum auth_mech mech;
	unsigned int id; /* AuthReplyData.id will contain this value */
};

/* Continued authentication request */
struct auth_continued_request_data {
	enum auth_request_type type; /* AUTH_REQUEST_CONTINUE */

	unsigned char cookie[AUTH_COOKIE_SIZE];
	unsigned int id; /* AuthReplyData.id will contain this value */

	size_t data_size;
	/* unsigned char data[]; */
};

/* Reply to authentication */
struct auth_reply_data {
	unsigned int id;
	unsigned char cookie[AUTH_COOKIE_SIZE];
	enum auth_result result;

	size_t data_size;
	/* unsigned char data[]; */
};

/* Request data associated to cookie */
struct auth_cookie_request_data {
	unsigned int id;
	unsigned int login_pid;
	unsigned char cookie[AUTH_COOKIE_SIZE];
};

/* Reply to cookie request */
struct auth_cookie_reply_data {
	unsigned int id;
	int success; /* FALSE if cookie wasn't found */

	char system_user[AUTH_MAX_USER_LEN]; /* system user, if available */
	char virtual_user[AUTH_MAX_VUSER_LEN]; /* for logging etc. */
	uid_t uid;
	gid_t gid;

	char home[AUTH_MAX_HOME_LEN];
	char mail[AUTH_MAX_MAIL_LEN];

	int chroot; /* chroot to home directory */
};

#endif
