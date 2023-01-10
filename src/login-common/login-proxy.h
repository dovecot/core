#ifndef LOGIN_PROXY_H
#define LOGIN_PROXY_H

#include "net.h"
#include "guid.h"
#include "auth-proxy.h"

/* Max. number of embedded proxying connections until proxying fails.
   This is intended to avoid an accidental configuration where two proxies
   keep connecting to each others, both thinking the other one is supposed to
   handle the user. This only works if both proxies support the Dovecot
   TTL extension feature. */
#define LOGIN_PROXY_TTL 7
#define LOGIN_PROXY_DEFAULT_HOST_IMMEDIATE_FAILURE_AFTER_SECS 30

#define LOGIN_PROXY_FAILURE_MSG "Account is temporarily unavailable."

struct client;
struct login_proxy;

enum login_proxy_failure_type {
	/* connect() failed or remote disconnected us. */
	LOGIN_PROXY_FAILURE_TYPE_CONNECT,
	/* Internal error. */
	LOGIN_PROXY_FAILURE_TYPE_INTERNAL,
	/* Internal configuration error. */
	LOGIN_PROXY_FAILURE_TYPE_INTERNAL_CONFIG,
	/* Remote command failed unexpectedly. */
	LOGIN_PROXY_FAILURE_TYPE_REMOTE,
	/* Remote isn't configured as expected (e.g. STARTTLS required, but
	   no such capability). */
	LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG,
	/* Remote server is unexpectedly violating the protocol standard. */
	LOGIN_PROXY_FAILURE_TYPE_PROTOCOL,
	/* Authentication failed to backend. The LOGIN/AUTH command reply was
	   already sent to the client. */
	LOGIN_PROXY_FAILURE_TYPE_AUTH,
	/* Authentication failed with a temporary failure code. Attempting it
	   again might work. */
	LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL,
	/* Authentication requests connecting to another host. The reason
	   string contains the host (and optionally :port). */
	LOGIN_PROXY_FAILURE_TYPE_AUTH_REDIRECT,
};

struct login_proxy_settings {
	const char *host;
	struct ip_addr ip, source_ip;
	in_port_t port;
	unsigned int connect_timeout_msecs;
	/* send a notification about proxy connection to proxy-notify pipe
	   every n seconds */
	unsigned int notify_refresh_secs;
	unsigned int host_immediate_failure_after_secs;
	enum auth_proxy_ssl_flags ssl_flags;
	const char *rawlog_dir;
};

/* Called when new input comes from proxy. */
typedef void login_proxy_input_callback_t(struct client *client);
/* Called when proxying fails. If reconnecting=TRUE, this is just an
   intermediate notification that the proxying will attempt to reconnect soon
   before failing. */
typedef void login_proxy_failure_callback_t(struct client *client,
					    enum login_proxy_failure_type type,
					    const char *reason,
					    bool reconnecting);
/* Redirect connection to destination (host:port). The callback needs to call
   login_proxy_redirect_finish() or login_proxy_failed(). */
typedef void login_proxy_redirect_callback_t(struct client *client,
					     struct event *event,
					     const char *destination);

/* Create a proxy to given host. Returns NULL if failed. Given callback is
   called when new input is available from proxy. */
int login_proxy_new(struct client *client, struct event *event,
		    const struct login_proxy_settings *set,
		    login_proxy_input_callback_t *input_callback,
		    login_proxy_failure_callback_t *failure_callback,
		    login_proxy_redirect_callback_t *redirect_callback);
/* Free the proxy. This should be called if authentication fails. */
void login_proxy_free(struct login_proxy **proxy);

/* Append to str host:ip[,host2:ip[,...]] path of redirects followed so far. */
void login_proxy_get_redirect_path(struct login_proxy *proxy, string_t *str);
/* Finish redirection to ip:port from a redirect callback. */
void login_proxy_redirect_finish(struct login_proxy *proxy,
				 const struct ip_addr *ip, in_port_t port);

/* Login proxying session has failed. Returns TRUE if the reconnection is
   attempted. */
bool login_proxy_failed(struct login_proxy *proxy, struct event *event,
			enum login_proxy_failure_type type, const char *reason);

/* Return TRUE if host/port/destuser combination points to same as current
   connection. */
bool login_proxy_is_ourself(const struct client *client, const char *host,
			    in_port_t port, const char *destuser);

/* Detach proxy from client. This is done after the authentication is
   successful and all that is left is the dummy proxying. */
void login_proxy_detach(struct login_proxy *proxy);

/* STARTTLS command was issued. */
int login_proxy_starttls(struct login_proxy *proxy);

struct istream *login_proxy_get_istream(struct login_proxy *proxy);
struct ostream *login_proxy_get_ostream(struct login_proxy *proxy);

void login_proxy_append_success_log_info(struct login_proxy *proxy,
					 string_t *str);
struct event *login_proxy_get_event(struct login_proxy *proxy);
const struct ip_addr *
login_proxy_get_source_host(const struct login_proxy *proxy);
const char *login_proxy_get_host(const struct login_proxy *proxy) ATTR_PURE;
const char *login_proxy_get_ip_str(const struct login_proxy *proxy) ATTR_PURE;
in_port_t login_proxy_get_port(const struct login_proxy *proxy) ATTR_PURE;
enum auth_proxy_ssl_flags
login_proxy_get_ssl_flags(const struct login_proxy *proxy) ATTR_PURE;
unsigned int
login_proxy_get_connect_timeout_msecs(const struct login_proxy *proxy) ATTR_PURE;
unsigned int
login_proxy_kick_user_connection(const char *user, const guid_128_t conn_guid);

void login_proxy_kill_idle(void);

unsigned int login_proxies_get_detached_count(void);
struct client *login_proxies_get_first_detached_client(void);

void login_proxy_init(const char *proxy_notify_pipe_path);
void login_proxy_deinit(void);

#endif
