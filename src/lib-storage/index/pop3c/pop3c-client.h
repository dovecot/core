#ifndef POP3C_CLIENT_H
#define POP3C_CLIENT_H

enum pop3c_capability {
	POP3C_CAPABILITY_PIPELINING	= 0x01,
	POP3C_CAPABILITY_TOP		= 0x02,
	POP3C_CAPABILITY_UIDL		= 0x04
};

enum pop3c_command_state {
	POP3C_COMMAND_STATE_OK,
	POP3C_COMMAND_STATE_ERR,
	POP3C_COMMAND_STATE_DISCONNECTED
};

enum pop3c_client_ssl_mode {
	POP3C_CLIENT_SSL_MODE_NONE,
	POP3C_CLIENT_SSL_MODE_IMMEDIATE,
	POP3C_CLIENT_SSL_MODE_STARTTLS
};

struct pop3c_client_settings {
	const char *host;
	unsigned int port;

	const char *master_user;
	const char *username;
	const char *password;

	const char *dns_client_socket_path;
	const char *temp_path_prefix;

	enum pop3c_client_ssl_mode ssl_mode;
	const char *ssl_ca_dir, *ssl_ca_file;
	bool ssl_verify;

	const char *rawlog_dir;
	const char *ssl_crypto_device;
	bool debug;
};

typedef void pop3c_login_callback_t(enum pop3c_command_state state,
				    const char *reply, void *context);

struct pop3c_client *
pop3c_client_init(const struct pop3c_client_settings *set);
void pop3c_client_deinit(struct pop3c_client **client);

void pop3c_client_run(struct pop3c_client *client);

void pop3c_client_login(struct pop3c_client *client,
			pop3c_login_callback_t *callback, void *context);

bool pop3c_client_is_connected(struct pop3c_client *client);
enum pop3c_capability
pop3c_client_get_capabilities(struct pop3c_client *client);

/* Returns 0 if received +OK reply, reply contains the text without the +OK.
   Returns -1 if received -ERR reply or disconnected. */
int pop3c_client_cmd_line(struct pop3c_client *client, const char *cmd,
			  const char **reply_r);
/* Send a command, don't care if it succeeds or not. */
void pop3c_client_cmd_line_async(struct pop3c_client *client, const char *cmd);
/* Returns 0 and stream if succeeded, -1 and error if received -ERR reply or
   disconnected. */
int pop3c_client_cmd_stream(struct pop3c_client *client, const char *cmd,
			    struct istream **input_r, const char **error_r);

#endif
