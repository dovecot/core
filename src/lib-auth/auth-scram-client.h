#ifndef AUTH_SCRAM_CLIENT_H
#define AUTH_SCRAM_CLIENT_H

enum auth_scram_client_state {
	AUTH_SCRAM_CLIENT_STATE_INIT = 0,
	AUTH_SCRAM_CLIENT_STATE_CLIENT_FIRST,
	AUTH_SCRAM_CLIENT_STATE_SERVER_FIRST,
	AUTH_SCRAM_CLIENT_STATE_CLIENT_FINAL,
	AUTH_SCRAM_CLIENT_STATE_SERVER_FINAL,
	AUTH_SCRAM_CLIENT_STATE_CLIENT_FINISH,
	AUTH_SCRAM_CLIENT_STATE_END,
};

struct auth_scram_client {
	pool_t pool;
	const struct hash_method *hmethod;
	
	/* Credentials */
	const char *authid, *authzid, *password;

	enum auth_scram_client_state state;

	/* Sent: */
	const char *nonce;
	const char *gs2_header;
	const char *client_first_message_bare;

	/* Received: */	
	const char *server_first_message;
	buffer_t *salt;
	unsigned int iter;

	unsigned char *server_signature;
};


void auth_scram_client_init(struct auth_scram_client *client_r, pool_t pool,
			    const struct hash_method *hmethod,
			    const char *authid, const char *authzid,
			    const char *password);
void auth_scram_client_deinit(struct auth_scram_client *client);

/* Returns TRUE if client is still due to send first output. */
bool auth_scram_client_state_client_first(struct auth_scram_client *client);

/* Pass server input to the client. Returns 0 upon success and -1 upon error
   (error_r is set accordingly). */
int auth_scram_client_input(struct auth_scram_client *client,
			    const unsigned char *input, size_t input_len,
			    const char **error_r);
/* Obtain output from client. This will assert fail if called out of sequence.
 */			    
void auth_scram_client_output(struct auth_scram_client *client,
			      const unsigned char **output_r,
			      size_t *output_len_r);

#endif
