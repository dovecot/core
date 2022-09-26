#ifndef AUTH_SCRAM_SERVER_H
#define AUTH_SCRAM_SERVER_H

#include "auth-scram.h"

struct auth_scram_server;

enum auth_scram_server_error {
	/* Success */
	AUTH_SCRAM_SERVER_ERROR_NONE,
	/* Protocol violation */
	AUTH_SCRAM_SERVER_ERROR_PROTOCOL_VIOLATION,
	/* Backend rejected the username provided by the client as invalid */
	AUTH_SCRAM_SERVER_ERROR_BAD_USERNAME,
	/* Something went wrong passing the login username to the backend */
	AUTH_SCRAM_SERVER_ERROR_BAD_LOGIN_USERNAME,
	/* Credentials lookup failed (nonexistent user or internal error). */
	AUTH_SCRAM_SERVER_ERROR_LOOKUP_FAILED,
	/* Credentials provided by client failed to verify against the
	   credentials looked up earlier. */
	AUTH_SCRAM_SERVER_ERROR_VERIFICATION_FAILED,
};

enum auth_scram_server_state {
	AUTH_SCRAM_SERVER_STATE_INIT = 0,
	AUTH_SCRAM_SERVER_STATE_CLIENT_FIRST,
	AUTH_SCRAM_SERVER_STATE_CREDENTIALS_LOOKUP,
	AUTH_SCRAM_SERVER_STATE_SERVER_FIRST,
	AUTH_SCRAM_SERVER_STATE_CLIENT_FINAL,
	AUTH_SCRAM_SERVER_STATE_SERVER_FINAL,
	AUTH_SCRAM_SERVER_STATE_CLIENT_FINISH,
	AUTH_SCRAM_SERVER_STATE_END,
	AUTH_SCRAM_SERVER_STATE_ERROR,
};

struct auth_scram_server_backend {
	/* Pass the authentication and authorization usernames to the
	   backend. */
	bool (*set_username)(struct auth_scram_server *server,
			     const char *username, const char **error_r);
	bool (*set_login_username)(struct auth_scram_server *server,
				   const char *username, const char **error_r);

	/* Instruct the backend to perform credentials lookup. The acquired
	   credentials are to be assigned to the provided key_data struct
	   eventually. If not immediately, the backend is supposed to call
	   auth_scram_server_output() later once the key_data struct is
	   initialized (i.e. when the lookup concludes). */
	int (*credentials_lookup)(struct auth_scram_server *server,
				  struct auth_scram_key_data *key_data);
};

struct auth_scram_server {
	pool_t pool;
	const struct hash_method *hash_method;

	/* Backend API */
	const struct auth_scram_server_backend *backend;
	void *context;

	enum auth_scram_server_state state;

	/* Sent: */
	const char *server_first_message;
	const char *snonce;

	/* Received: */
	const char *gs2_header;
	const char *cnonce;
	const char *client_first_message_bare;
	const char *client_final_message_without_proof;
	buffer_t *proof;

	/* Looked up: */
	struct auth_scram_key_data key_data;
};

void auth_scram_server_init(struct auth_scram_server *server_r, pool_t pool,
			    const struct hash_method *hmethod,
			    const struct auth_scram_server_backend *backend);
void auth_scram_server_deinit(struct auth_scram_server *server);

/* Returns TRUE if authentication was concluded successfully. */
bool auth_scram_server_acces_granted(struct auth_scram_server *server);

/* Pass client input to the server. Returns 1 if server output is available, 0
   if no server output is available yet (e.g. pending credentials lookup), and
   -1 upon error (error_code_r and error_r are set accordingly). */
int auth_scram_server_input(struct auth_scram_server *server,
			    const unsigned char *input, size_t input_len,
			    enum auth_scram_server_error *error_code_r,
			    const char **error_r);
/* Obtain output from server. This will assert fail if called out of sequence.
   Returns TRUE if this is the last authentication step and success may be
   indicated to the client or FALSE when the authentication handshake continues.
 */
bool auth_scram_server_output(struct auth_scram_server *server,
			      const unsigned char **output_r,
			      size_t *output_len_r);

#endif
