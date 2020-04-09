#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

struct module;

#include "net.h"
#include "login-proxy.h"
#include "sasl-server.h"
#include "master-login.h" /* for LOGIN_MAX_SESSION_ID_LEN */

#define LOGIN_MAX_SESSION_ID_LEN 64
#define LOGIN_MAX_MASTER_PREFIX_LEN 128
#define LOGIN_MAX_CLIENT_ID_LEN 256

/* max. size of input buffer. this means:

   IMAP: Max. length of command's all parameters. SASL-IR is read into
         a separate larger buffer.
   POP3: Max. length of a command line (spec says 512 would be enough)
*/
#define LOGIN_MAX_INBUF_SIZE \
	(MASTER_AUTH_MAX_DATA_SIZE - LOGIN_MAX_MASTER_PREFIX_LEN - \
	 LOGIN_MAX_SESSION_ID_LEN)
/* max. size of output buffer. if it gets full, the client is disconnected.
   SASL authentication gives the largest output. */
#define LOGIN_MAX_OUTBUF_SIZE 4096

/* Max. length of SASL authentication buffer. */
#define LOGIN_MAX_AUTH_BUF_SIZE 8192

/* Disconnect client after this many milliseconds if it hasn't managed
   to log in yet. */
#define CLIENT_LOGIN_TIMEOUT_MSECS (MASTER_LOGIN_TIMEOUT_SECS*1000)

#define AUTH_SERVER_WAITING_MSG \
	"Waiting for authentication process to respond.."
#define AUTH_MASTER_WAITING_MSG \
	"Waiting for authentication master process to respond.."

struct master_service_connection;

enum client_disconnect_reason {
	CLIENT_DISCONNECT_TIMEOUT,
	CLIENT_DISCONNECT_SYSTEM_SHUTDOWN,
	CLIENT_DISCONNECT_RESOURCE_CONSTRAINT,
	CLIENT_DISCONNECT_INTERNAL_ERROR
};

enum client_auth_fail_code {
	CLIENT_AUTH_FAIL_CODE_NONE = 0,
	CLIENT_AUTH_FAIL_CODE_AUTHZFAILED,
	CLIENT_AUTH_FAIL_CODE_TEMPFAIL,
	CLIENT_AUTH_FAIL_CODE_USER_DISABLED,
	CLIENT_AUTH_FAIL_CODE_PASS_EXPIRED,
	CLIENT_AUTH_FAIL_CODE_INVALID_BASE64,
	CLIENT_AUTH_FAIL_CODE_LOGIN_DISABLED,
	CLIENT_AUTH_FAIL_CODE_MECH_INVALID,
	CLIENT_AUTH_FAIL_CODE_MECH_SSL_REQUIRED,
	CLIENT_AUTH_FAIL_CODE_ANONYMOUS_DENIED,
};

enum client_auth_result {
	CLIENT_AUTH_RESULT_SUCCESS,
	CLIENT_AUTH_RESULT_REFERRAL_SUCCESS,
	CLIENT_AUTH_RESULT_REFERRAL_NOLOGIN,
	CLIENT_AUTH_RESULT_ABORTED,
	CLIENT_AUTH_RESULT_AUTHFAILED,
	CLIENT_AUTH_RESULT_AUTHFAILED_REASON,
	CLIENT_AUTH_RESULT_AUTHZFAILED,
	CLIENT_AUTH_RESULT_TEMPFAIL,
	CLIENT_AUTH_RESULT_PASS_EXPIRED,
	CLIENT_AUTH_RESULT_SSL_REQUIRED,
	CLIENT_AUTH_RESULT_INVALID_BASE64,
	CLIENT_AUTH_RESULT_LOGIN_DISABLED,
	CLIENT_AUTH_RESULT_MECH_INVALID,
	CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED,
	CLIENT_AUTH_RESULT_ANONYMOUS_DENIED
};

struct client_auth_reply {
	const char *master_user, *reason;
	enum client_auth_fail_code fail_code;

	/* for proxying */
	const char *host, *hostip, *source_ip;
	const char *destuser, *password, *proxy_mech;
	in_port_t port;
	unsigned int proxy_timeout_msecs;
	unsigned int proxy_refresh_secs;
	enum login_proxy_ssl_flags ssl_flags;

	/* all the key=value fields returned by passdb */
	const char *const *all_fields;

	bool proxy:1;
	bool proxy_nopipelining:1;
	bool proxy_not_trusted:1;
	bool nologin:1;
};

struct client_vfuncs {
	struct client *(*alloc)(pool_t pool);
	void (*create)(struct client *client, void **other_sets);
	void (*destroy)(struct client *client);
	void (*notify_auth_ready)(struct client *client);
	void (*notify_disconnect)(struct client *client,
				  enum client_disconnect_reason reason,
				  const char *text);
	void (*notify_status)(struct client *client,
			      bool bad, const char *text);
	void (*notify_starttls)(struct client *client,
				bool success, const char *text);
	void (*starttls)(struct client *client);
	void (*input)(struct client *client);
	bool (*sasl_filter_mech)(struct client *client,
				 struct auth_mech_desc *mech);
	bool (*sasl_check_login)(struct client *client);
	void (*auth_send_challenge)(struct client *client, const char *data);
	void (*auth_parse_response)(struct client *client);
	void (*auth_result)(struct client *client,
			    enum client_auth_result result,
			    const struct client_auth_reply *reply,
			    const char *text);
	void (*proxy_reset)(struct client *client);
	int (*proxy_parse_line)(struct client *client, const char *line);
	void (*proxy_error)(struct client *client, const char *text);
	const char *(*proxy_get_state)(struct client *client);
	void (*send_raw_data)(struct client *client,
			      const void *data, size_t size);
	bool (*input_next_cmd)(struct client *client);
	void (*free)(struct client *client);
};

struct client {
	/* If disconnected=FALSE, the client is in "clients" list.
	   If fd_proxying=TRUE, the client is in "client_fd_proxies" list.
	   Otherwise, either the client will soon be freed or it's only
	   referenced via "login_proxies" which doesn't use these pointers. */
	struct client *prev, *next;

	pool_t pool;
	/* this pool gets free'd once proxying starts */
	pool_t preproxy_pool;
	struct client_vfuncs v;
	struct client_vfuncs *vlast;

	time_t created;
	int refcount;
	struct event *event;

	struct ip_addr local_ip;
	struct ip_addr ip;
	struct ip_addr real_remote_ip, real_local_ip;
	in_port_t local_port, remote_port;
	in_port_t real_local_port, real_remote_port;
	struct ssl_iostream *ssl_iostream;
	const struct login_settings *set;
	const struct master_service_ssl_settings *ssl_set;
	const char *session_id, *listener_name, *postlogin_socket_path;
	const char *local_name;
	const char *client_cert_common_name;

	string_t *client_id;
	string_t *forward_fields;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct iostream_proxy *iostream_fd_proxy;
	struct timeout *to_auth_waiting;
	struct timeout *to_disconnect;

	unsigned char *master_data_prefix;
	unsigned int master_data_prefix_len;

	struct login_proxy *login_proxy;
	char *proxy_user, *proxy_master_user, *proxy_password;
	const struct dsasl_client_mech *proxy_mech;
	struct dsasl_client *proxy_sasl_client;
	unsigned int proxy_ttl;

	char *auth_mech_name;
	struct auth_client_request *auth_request;
	string_t *auth_response;
	time_t auth_first_started, auth_finished;
	const char *sasl_final_resp;
	const char *const *auth_passdb_args;

	unsigned int master_auth_id;
	unsigned int master_tag;
	sasl_server_callback_t *sasl_callback;

	unsigned int bad_counter;
	unsigned int auth_attempts, auth_successes;
	enum client_auth_fail_code last_auth_fail;
	pid_t mail_pid;

	/* Module-specific contexts. */
	ARRAY(union login_client_module_context *) module_contexts;

	char *virtual_user, *virtual_user_orig, *virtual_auth_user;
	/* passdb user_* fields are set here after a successful auth.
	   This is a NULL-terminated array where fields are in the same order
	   as in global_alt_usernames. If some field doesn't exist, it's "".
	   Can also be NULL if there are no user_* fields. */
	const char **alt_usernames;
	/* director_username_hash cached, if non-zero */
	unsigned int director_username_hash_cache;

	bool create_finished:1;
	bool disconnected:1;
	bool destroyed:1;
	bool input_blocked:1;
	bool login_success:1;
	bool no_extra_disconnect_reason:1;
	bool starttls:1;
	bool tls:1;
	bool proxied_ssl:1;
	bool secured:1;
	bool ssl_secured:1;
	bool trusted:1;
	bool ssl_servername_settings_read:1;
	bool banner_sent:1;
	bool authenticating:1;
	bool auth_try_aborted:1;
	bool auth_initializing:1;
	bool auth_process_comm_fail:1;
	bool auth_anonymous:1;
	bool proxy_auth_failed:1;
	bool proxy_nopipelining:1;
	bool proxy_not_trusted:1;
	bool auth_waiting:1;
	bool notified_auth_ready:1;
	bool notified_disconnect:1;
	bool fd_proxying:1;
	/* ... */
};

union login_client_module_context {
	struct client_vfuncs super;
	struct login_module_register *reg;
};

struct login_client_hooks {
	void (*client_allocated)(struct client *client);
};

extern struct client *clients;

typedef void login_client_allocated_func_t(struct client *client);

void login_client_hooks_add(struct module *module,
			    const struct login_client_hooks *hooks);
void login_client_hooks_remove(const struct login_client_hooks *hooks);

struct client *
client_alloc(int fd, pool_t pool,
	     const struct master_service_connection *conn,
	     const struct login_settings *set,
	     const struct master_service_ssl_settings *ssl_set);
void client_init(struct client *client, void **other_sets);
void client_disconnect(struct client *client, const char *reason);
void client_destroy(struct client *client, const char *reason);
/* Destroy the client after a successful login. Either the client fd was
   sent to the post-login process, or the connection will be proxied. */
void client_destroy_success(struct client *client, const char *reason);

void client_ref(struct client *client);
bool client_unref(struct client **client) ATTR_NOWARN_UNUSED_RESULT;

int client_init_ssl(struct client *client);
void client_cmd_starttls(struct client *client);

int client_get_plaintext_fd(struct client *client, int *fd_r, bool *close_fd_r);

unsigned int clients_get_count(void) ATTR_PURE;
unsigned int clients_get_fd_proxies_count(void);
struct client *clients_get_first_fd_proxy(void);

void client_add_forward_field(struct client *client, const char *key,
			      const char *value);
void client_set_title(struct client *client);
const char *client_get_extra_disconnect_reason(struct client *client);

void client_auth_respond(struct client *client, const char *response);
void client_auth_abort(struct client *client);
bool client_is_tls_enabled(struct client *client);
void client_auth_fail(struct client *client, const char *text);
const char *client_get_session_id(struct client *client);

bool client_read(struct client *client);

void client_input(struct client *client);

static inline bool
client_does_custom_io(struct client *client)
{
	return (client->v.input == NULL);
}

void client_notify_auth_ready(struct client *client);
void client_notify_status(struct client *client, bool bad, const char *text);
void client_notify_disconnect(struct client *client,
			      enum client_disconnect_reason reason,
			      const char *text);

void client_send_raw_data(struct client *client, const void *data, size_t size);
void client_send_raw(struct client *client, const char *data);
void client_common_send_raw_data(struct client *client,
				 const void *data, size_t size);
void client_common_default_free(struct client *client);

void client_set_auth_waiting(struct client *client);
void client_auth_send_challenge(struct client *client, const char *data);
void client_auth_parse_response(struct client *client);
int client_auth_begin(struct client *client, const char *mech_name,
		      const char *init_resp);
int client_auth_begin_private(struct client *client, const char *mech_name,
			      const char *init_resp);
bool client_check_plaintext_auth(struct client *client, bool pass_sent);
int client_auth_read_line(struct client *client);

void client_proxy_finish_destroy_client(struct client *client);
void client_proxy_log_failure(struct client *client, const char *line);
void client_proxy_failed(struct client *client, bool send_line);
const char *client_proxy_get_state(struct client *client);

void clients_notify_auth_connected(void);
void client_destroy_oldest(void);
void clients_destroy_all(void);
void clients_destroy_all_reason(const char *reason);

void client_destroy_fd_proxies(void);
void client_common_init(void);
void client_common_deinit(void);

#endif
