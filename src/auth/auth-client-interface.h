#ifndef __AUTH_CLIENT_INTERFACE_H
#define __AUTH_CLIENT_INTERFACE_H

/* max. size for auth_client_request_continue.data[] */
#define AUTH_CLIENT_MAX_REQUEST_DATA_SIZE 4096

/* Client process must finish with single authentication requests in this time,
   or the whole connection will be killed. */
#define AUTH_REQUEST_TIMEOUT 120

enum auth_mech {
	AUTH_MECH_PLAIN		= 0x01,
	AUTH_MECH_DIGEST_MD5	= 0x02,
	AUTH_MECH_ANONYMOUS	= 0x04,

	AUTH_MECH_COUNT
};

enum auth_protocol {
	AUTH_PROTOCOL_IMAP	= 0x01,
	AUTH_PROTOCOL_POP3	= 0x02
};

enum auth_client_request_type {
	AUTH_CLIENT_REQUEST_NEW = 1,
        AUTH_CLIENT_REQUEST_CONTINUE
};

enum auth_client_result {
	AUTH_CLIENT_RESULT_CONTINUE = 1,
	AUTH_CLIENT_RESULT_SUCCESS,
	AUTH_CLIENT_RESULT_FAILURE
};

/* Client -> Server */
struct auth_client_handshake_request {
	unsigned int client_pid; /* unique identifier for client process */
};

/* Server -> Client */
struct auth_client_handshake_reply {
	unsigned int server_pid; /* unique auth process identifier */
	enum auth_mech auth_mechanisms; /* valid authentication mechanisms */
};

/* New authentication request */
struct auth_client_request_new {
	enum auth_client_request_type type; /* AUTH_CLIENT_REQUEST_NEW */
	unsigned int id; /* unique ID for the request */

	enum auth_mech mech;
	enum auth_protocol protocol;
};

/* Continue authentication request */
struct auth_client_request_continue {
	enum auth_client_request_type type; /* AUTH_CLIENT_REQUEST_CONTINUE */
	unsigned int id;

	size_t data_size;
	/* unsigned char data[]; */
};

/* Reply to authentication */
struct auth_client_request_reply {
	unsigned int id;

	enum auth_client_result result;

	/* variable width data, indexes into data[].
	   Ignore if it points outside data_size. */
	size_t username_idx; /* NUL-terminated */
	size_t reply_idx; /* last, non-NUL terminated */

	size_t data_size;
	/* unsigned char data[]; */
};

#endif
