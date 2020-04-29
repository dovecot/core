#ifndef LOGIN_PROXY_H
#define LOGIN_PROXY_H

#include "net.h"

/* Max. number of embedded proxying connections until proxying fails.
   This is intended to avoid an accidental configuration where two proxies
   keep connecting to each others, both thinking the other one is supposed to
   handle the user. This only works if both proxies support the Dovecot
   TTL extension feature. */
#define LOGIN_PROXY_TTL 5

struct client;
struct login_proxy;

enum login_proxy_ssl_flags {
	/* Use SSL/TLS enabled */
	PROXY_SSL_FLAG_YES	= 0x01,
	/* Don't do SSL handshake immediately after connected */
	PROXY_SSL_FLAG_STARTTLS	= 0x02,
	/* Don't require that the received certificate is valid */
	PROXY_SSL_FLAG_ANY_CERT	= 0x04
};

struct login_proxy_settings {
	const char *host;
	struct ip_addr ip, source_ip;
	in_port_t port;
	unsigned int connect_timeout_msecs;
	/* send a notification about proxy connection to proxy-notify pipe
	   every n seconds */
	unsigned int notify_refresh_secs;
	enum login_proxy_ssl_flags ssl_flags;
};

/* Called when new input comes from proxy. */
typedef void proxy_callback_t(struct client *client);

/* Create a proxy to given host. Returns NULL if failed. Given callback is
   called when new input is available from proxy. */
int login_proxy_new(struct client *client, struct event *event,
		    const struct login_proxy_settings *set,
		    proxy_callback_t *callback);
/* Free the proxy. This should be called if authentication fails. */
void login_proxy_free(struct login_proxy **proxy);

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
const char *login_proxy_get_host(const struct login_proxy *proxy) ATTR_PURE;
in_port_t login_proxy_get_port(const struct login_proxy *proxy) ATTR_PURE;
enum login_proxy_ssl_flags
login_proxy_get_ssl_flags(const struct login_proxy *proxy) ATTR_PURE;

void login_proxy_kill_idle(void);

unsigned int login_proxies_get_detached_count(void);
struct client *login_proxies_get_first_detached_client(void);

void login_proxy_init(const char *proxy_notify_pipe_path);
void login_proxy_deinit(void);

#endif
