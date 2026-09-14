#ifndef POP3C_CLIENT_H
#define POP3C_CLIENT_H

#include "net.h"
#include "pop3c-client-settings.h"

struct pop3c_client;

enum pop3c_capability {
	POP3C_CAPABILITY_PIPELINING	= 0x01,
	POP3C_CAPABILITY_TOP		= 0x02,
	POP3C_CAPABILITY_UIDL		= 0x04,
	POP3C_CAPABILITY_STLS           = 0x08,
	POP3C_CAPABILITY_SASL		= 0x10,
};

enum pop3c_command_state {
	POP3C_COMMAND_STATE_OK,
	POP3C_COMMAND_STATE_ERR,
	POP3C_COMMAND_STATE_DISCONNECTED
};
extern const char *pop3c_command_state_names[];

enum pop3c_client_ssl_mode {
	POP3C_CLIENT_SSL_MODE_NONE,
	POP3C_CLIENT_SSL_MODE_IMMEDIATE,
	POP3C_CLIENT_SSL_MODE_STARTTLS
};

enum pop3c_parameter_flags {
	POP3C_PARAMETER_CLIENT_DISABLED = BIT(1),
};

struct pop3c_parameters {
	const char *temp_path_prefix;

	enum pop3c_parameter_flags flags;
};

typedef void pop3c_login_callback_t(enum pop3c_command_state state,
				    const char *reply, void *context);
typedef void pop3c_cmd_callback_t(enum pop3c_command_state state,
				  const char *reply, void *context);

int pop3c_client_init(const struct pop3c_parameters *params,
		      struct event *event_parent,
		      struct pop3c_client **client_r, const char **error_r);
void pop3c_client_deinit(struct pop3c_client **client);

int pop3c_client_settings_match(struct event *event1, struct event *event2,
				const char **error_r);

void pop3c_client_login(struct pop3c_client *client,
			pop3c_login_callback_t *callback, void *context);

bool pop3c_client_is_connected(struct pop3c_client *client);
enum pop3c_capability
pop3c_client_get_capabilities(struct pop3c_client *client);

/* Returns 0 if received +OK reply, reply contains the text without the +OK.
   Returns -1 if received -ERR reply or disconnected. */
int pop3c_client_cmd_line(struct pop3c_client *client, const char *cmdline,
			  const char **reply_r);
/* Start the command asynchronously. Call the callback when finished. */
struct pop3c_client_cmd *
pop3c_client_cmd_line_async(struct pop3c_client *client, const char *cmdline,
			    pop3c_cmd_callback_t *callback, void *context);
/* Send a command, don't care if it succeeds or not. */
void pop3c_client_cmd_line_async_nocb(struct pop3c_client *client,
				      const char *cmdline);
/* Returns 0 and stream if succeeded, -1 and error if received -ERR reply or
   disconnected. */
int pop3c_client_cmd_stream(struct pop3c_client *client, const char *cmdline,
			    struct istream **input_r, const char **error_r);
/* Start the command asynchronously. Call the callback when finished. */
struct istream *
pop3c_client_cmd_stream_async(struct pop3c_client *client, const char *cmdline,
			      pop3c_cmd_callback_t *callback, void *context);
/* Wait for the next async command to finish. It's an error to call this when
   there are no pending async commands. */
void pop3c_client_wait_one(struct pop3c_client *client);

#endif
