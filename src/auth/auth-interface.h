#ifndef __AUTH_INTERFACE_H
#define __AUTH_INTERFACE_H

#define AUTH_COOKIE_SIZE		16

#define AUTH_MAX_REQUEST_DATA_SIZE	4096
#define AUTH_MAX_REPLY_DATA_SIZE	4096

#define AUTH_MAX_USER_LEN		64
#define AUTH_MAX_VUSER_LEN		256
#define AUTH_MAX_HOME_LEN		256
#define AUTH_MAX_MAIL_LEN		256

typedef enum {
	AUTH_REQUEST_NONE, /* must not be requested */
	AUTH_REQUEST_INIT,
        AUTH_REQUEST_CONTINUE
} AuthRequestType;

typedef enum {
	AUTH_RESULT_INTERNAL_FAILURE, /* never sent by imap-auth */

	AUTH_RESULT_CONTINUE,
	AUTH_RESULT_SUCCESS,
	AUTH_RESULT_FAILURE
} AuthResult;

typedef enum {
	AUTH_METHOD_PLAIN	= 0x01,
	AUTH_METHOD_DIGEST_MD5	= 0x02,

	AUTH_METHODS_COUNT	= 2
} AuthMethod;

/* Initialization reply, sent after client is connected */
typedef struct {
	unsigned int auth_process; /* unique auth process identifier */
	AuthMethod auth_methods; /* valid authentication methods */
} AuthInitData;

/* Initialization handshake from client. */
typedef struct {
	unsigned int pid; /* unique identifier for client process */
} ClientAuthInitData;

/* New authentication request */
typedef struct {
	AuthRequestType type; /* AUTH_REQUEST_INIT */

	AuthMethod method;
	unsigned int id; /* AuthReplyData.id will contain this value */
} AuthInitRequestData;

/* Continued authentication request */
typedef struct {
	AuthRequestType type; /* AUTH_REQUEST_CONTINUE */

	unsigned char cookie[AUTH_COOKIE_SIZE];
	unsigned int id; /* AuthReplyData.id will contain this value */

	size_t data_size;
	/* unsigned char data[]; */
} AuthContinuedRequestData;

/* Reply to authentication */
typedef struct {
	unsigned int id;
	unsigned char cookie[AUTH_COOKIE_SIZE];
	AuthResult result;

	size_t data_size;
	/* unsigned char data[]; */
} AuthReplyData;

/* Request data associated to cookie */
typedef struct {
	unsigned int id;
	unsigned int login_pid;
	unsigned char cookie[AUTH_COOKIE_SIZE];
} AuthCookieRequestData;

/* Reply to cookie request */
typedef struct {
	unsigned int id;
	int success; /* FALSE if cookie wasn't found */

	char system_user[AUTH_MAX_USER_LEN]; /* system user, if available */
	char virtual_user[AUTH_MAX_VUSER_LEN]; /* for logging etc. */
	uid_t uid;
	gid_t gid;

	char home[AUTH_MAX_HOME_LEN];
	char mail[AUTH_MAX_MAIL_LEN];

	int chroot; /* chroot to home directory */
} AuthCookieReplyData;

#endif
