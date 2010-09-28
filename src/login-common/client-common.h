#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

#include "network.h"
#include "login-proxy.h"
#include "sasl-server.h"

/* max. size of input buffer. this means:

   IMAP: Max. length of a single parameter
   POP3: Max. length of a command line (spec says 512 would be enough)
*/
#define LOGIN_MAX_INBUF_SIZE 1024
/* max. size of output buffer. if it gets full, the client is disconnected.
   SASL authentication gives the largest output. */
#define LOGIN_MAX_OUTBUF_SIZE 4096

/* Disconnect client after this many milliseconds if it hasn't managed
   to log in yet. */
#define CLIENT_LOGIN_TIMEOUT_MSECS (MASTER_LOGIN_TIMEOUT_SECS*1000)

#define AUTH_SERVER_WAITING_MSG \
	"Waiting for authentication process to respond.."
#define AUTH_MASTER_WAITING_MSG \
	"Waiting for authentication master process to respond.."

enum client_cmd_reply {
	CLIENT_CMD_REPLY_OK,
	CLIENT_CMD_REPLY_AUTH_FAILED,
	CLIENT_CMD_REPLY_AUTHZ_FAILED,
	CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
	CLIENT_CMD_REPLY_AUTH_FAIL_REASON,
	CLIENT_CMD_REPLY_AUTH_FAIL_NOSSL,
	CLIENT_CMD_REPLY_BAD,
	CLIENT_CMD_REPLY_BYE,
	CLIENT_CMD_REPLY_STATUS,
	CLIENT_CMD_REPLY_STATUS_BAD
};

struct client_auth_reply {
	const char *master_user, *reason;
	/* for proxying */
	const char *host, *destuser, *password;
	unsigned int port;
	unsigned int proxy_timeout_msecs;
	unsigned int proxy_refresh_secs;
	enum login_proxy_ssl_flags ssl_flags;

	unsigned int proxy:1;
	unsigned int temp:1;
	unsigned int nologin:1;
	unsigned int authz_failure:1;
};

struct client_vfuncs {
	struct client *(*alloc)(pool_t pool);
	void (*create)(struct client *client, void **other_sets);
	void (*destroy)(struct client *client);
	void (*send_greeting)(struct client *client);
	void (*starttls)(struct client *client);
	void (*input)(struct client *client);
	void (*send_line)(struct client *client, enum client_cmd_reply reply,
			  const char *text);
	bool (*auth_handle_reply)(struct client *client,
				  const struct client_auth_reply *reply);
	void (*auth_send_challenge)(struct client *client, const char *data);
	int (*auth_parse_response)(struct client *client);
	void (*proxy_reset)(struct client *client);
	int (*proxy_parse_line)(struct client *client, const char *line);
};

struct client {
	struct client *prev, *next;
	pool_t pool;
	struct client_vfuncs v;

	time_t created;
	int refcount;

	struct ip_addr local_ip;
	struct ip_addr ip;
	unsigned int local_port, remote_port;
	struct ssl_proxy *ssl_proxy;
	const struct login_settings *set;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct timeout *to_auth_waiting;
	struct timeout *to_disconnect;

	unsigned char *master_data_prefix;
	unsigned int master_data_prefix_len;

	struct login_proxy *login_proxy;
	char *proxy_user, *proxy_master_user, *proxy_password;
	unsigned int proxy_state;

	char *auth_mech_name;
	struct auth_client_request *auth_request;
	string_t *auth_response;

	unsigned int master_auth_id;
	unsigned int master_tag;
	sasl_server_callback_t *sasl_callback;

	unsigned int bad_counter;
	unsigned int auth_attempts;
	pid_t mail_pid;

	char *virtual_user;
	unsigned int destroyed:1;
	unsigned int input_blocked:1;
	unsigned int login_success:1;
	unsigned int greeting_sent:1;
	unsigned int starttls:1;
	unsigned int tls:1;
	unsigned int secured:1;
	unsigned int trusted:1;
	unsigned int authenticating:1;
	unsigned int auth_tried_disabled_plaintext:1;
	unsigned int auth_tried_unsupported_mech:1;
	unsigned int auth_try_aborted:1;
	unsigned int auth_initializing:1;
	/* ... */
};

extern struct client *clients;
extern struct client_vfuncs client_vfuncs;

struct client *
client_create(int fd, bool ssl, pool_t pool,
	      const struct login_settings *set, void **other_sets,
	      const struct ip_addr *local_ip, const struct ip_addr *remote_ip);
void client_destroy(struct client *client, const char *reason);
void client_destroy_success(struct client *client, const char *reason);
void client_destroy_internal_failure(struct client *client);

void client_ref(struct client *client);
bool client_unref(struct client **client);

void client_cmd_starttls(struct client *client);

unsigned int clients_get_count(void) ATTR_PURE;

void client_set_title(struct client *client);
void client_log(struct client *client, const char *msg);
void client_log_err(struct client *client, const char *msg);
const char *client_get_extra_disconnect_reason(struct client *client);
bool client_is_trusted(struct client *client);
void client_auth_failed(struct client *client);

bool client_read(struct client *client);
void client_input(struct client *client);

void client_send_line(struct client *client, enum client_cmd_reply reply,
		      const char *text);
void client_send_raw_data(struct client *client, const void *data, size_t size);
void client_send_raw(struct client *client, const char *data);

void client_set_auth_waiting(struct client *client);
void client_auth_send_challenge(struct client *client, const char *data);
int client_auth_parse_response(struct client *client);
int client_auth_begin(struct client *client, const char *mech_name,
		      const char *init_resp);
bool client_check_plaintext_auth(struct client *client, bool pass_sent);

void client_proxy_finish_destroy_client(struct client *client);
void client_proxy_log_failure(struct client *client, const char *line);
void client_proxy_failed(struct client *client, bool send_line);

void clients_notify_auth_connected(void);
void client_destroy_oldest(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
