#ifndef __AUTH_LOGIN_INTERFACE_H
#define __AUTH_LOGIN_INTERFACE_H

/* max. size for auth_login_request_continue.data[] */
#define AUTH_LOGIN_MAX_REQUEST_DATA_SIZE 4096

enum auth_mech {
	AUTH_MECH_PLAIN		= 0x01,
	AUTH_MECH_DIGEST_MD5	= 0x02,

	AUTH_MECH_COUNT
};

enum auth_protocol {
	AUTH_PROTOCOL_IMAP	= 0x01,
	AUTH_PROTOCOL_POP3	= 0x02
};

enum auth_login_request_type {
	AUTH_LOGIN_REQUEST_NEW = 1,
        AUTH_LOGIN_REQUEST_CONTINUE
};

enum auth_login_result {
	AUTH_LOGIN_RESULT_CONTINUE = 1,
	AUTH_LOGIN_RESULT_SUCCESS,
	AUTH_LOGIN_RESULT_FAILURE
};

/* Incoming handshake */
struct auth_login_handshake_input {
	unsigned int pid; /* unique identifier for client process */
};

/* Outgoing handshake */
struct auth_login_handshake_output {
	unsigned int pid; /* unique auth process identifier */
	enum auth_mech auth_mechanisms; /* valid authentication mechanisms */
};

/* New authentication request */
struct auth_login_request_new {
	enum auth_login_request_type type; /* AUTH_LOGIN_REQUEST_NEW */
	unsigned int id; /* unique ID for the request */

	enum auth_mech mech;
	enum auth_protocol protocol;
};

/* Continue authentication request */
struct auth_login_request_continue {
	enum auth_login_request_type type; /* AUTH_LOGIN_REQUEST_CONTINUE */
	unsigned int id;

	size_t data_size;
	/* unsigned char data[]; */
};

/* Reply to authentication */
struct auth_login_reply {
	unsigned int id;

	enum auth_login_result result;

	/* variable width data, indexes into data[].
	   Ignore if it points outside data_size. */
	size_t username_idx; /* NUL-terminated */
	size_t realm_idx; /* NUL-terminated */
	size_t reply_idx; /* last, non-NUL terminated */

	size_t data_size;
	/* unsigned char data[]; */
};

#endif
