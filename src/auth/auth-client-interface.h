#ifndef __AUTH_CLIENT_INTERFACE_H
#define __AUTH_CLIENT_INTERFACE_H

/* max. size for auth_client_request_continue.data[] */
#define AUTH_CLIENT_MAX_REQUEST_DATA_SIZE 4096

/* Client process must finish with single authentication requests in this time,
   or the whole connection will be killed. */
#define AUTH_REQUEST_TIMEOUT 120

enum auth_client_request_new_flags {
	AUTH_CLIENT_FLAG_SSL_ENABLED		= 0x01,
	AUTH_CLIENT_FLAG_SSL_VALID_CLIENT_CERT	= 0x02
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

struct auth_client_handshake_mech_desc {
	uint32_t name_idx;
	unsigned int plaintext:1;
	unsigned int advertise:1;
};

/* Server -> Client */
struct auth_client_handshake_reply {
	unsigned int server_pid; /* unique auth process identifier */
	unsigned int connect_uid; /* unique connection identifier */

	uint32_t mech_count;
	uint32_t data_size;
	/* struct auth_client_handshake_mech_desc mech_desc[auth_mech_count]; */
};

/* New authentication request */
struct auth_client_request_new {
	enum auth_client_request_type type; /* AUTH_CLIENT_REQUEST_NEW */
	unsigned int id; /* unique ID for the request */

	enum auth_client_request_new_flags flags;

	uint32_t ip_family; /* if non-zero, data begins with local/remote IPs */

	uint32_t protocol_idx;
	uint32_t mech_idx;
	uint32_t initial_resp_idx;

	uint32_t data_size;
	/* unsigned char data[]; */
};
#define AUTH_CLIENT_REQUEST_HAVE_INITIAL_RESPONSE(request) \
        ((request)->initial_resp_idx != (request)->data_size)

/* Continue authentication request */
struct auth_client_request_continue {
	enum auth_client_request_type type; /* AUTH_CLIENT_REQUEST_CONTINUE */
	unsigned int id;

	uint32_t data_size;
	/* unsigned char data[]; */
};

/* Reply to authentication */
struct auth_client_request_reply {
	unsigned int id;

	enum auth_client_result result;

	/* variable width data, indexes into data[].
	   Ignore if it points outside data_size. */
	uint32_t username_idx; /* NUL-terminated */
	uint32_t reply_idx; /* last, non-NUL terminated */

	uint32_t data_size;
	/* unsigned char data[]; */
};

#endif
