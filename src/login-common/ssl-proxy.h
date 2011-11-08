#ifndef SSL_PROXY_H
#define SSL_PROXY_H

struct ip_addr;
struct ssl_proxy;
struct login_settings;
struct client;

extern bool ssl_initialized;

typedef int ssl_handshake_callback_t(void *context);

/* establish SSL connection with the given fd, returns a new fd which you
   must use from now on, or -1 if error occurred. Unless -1 is returned,
   the given fd must be simply forgotten. */
int ssl_proxy_alloc(int fd, const struct ip_addr *ip,
		    const struct login_settings *set,
		    struct ssl_proxy **proxy_r);
int ssl_proxy_client_alloc(int fd, struct ip_addr *ip,
			   const struct login_settings *set,
			   ssl_handshake_callback_t *callback, void *context,
			   struct ssl_proxy **proxy_r);
void ssl_proxy_start(struct ssl_proxy *proxy);
void ssl_proxy_set_client(struct ssl_proxy *proxy, struct client *client);
bool ssl_proxy_has_valid_client_cert(const struct ssl_proxy *proxy) ATTR_PURE;
bool ssl_proxy_has_broken_client_cert(struct ssl_proxy *proxy);
int ssl_proxy_cert_match_name(struct ssl_proxy *proxy, const char *verify_name);
const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy);
bool ssl_proxy_is_handshaked(const struct ssl_proxy *proxy) ATTR_PURE;
const char *ssl_proxy_get_last_error(const struct ssl_proxy *proxy) ATTR_PURE;
const char *ssl_proxy_get_security_string(struct ssl_proxy *proxy);
const char *ssl_proxy_get_compression(struct ssl_proxy *proxy);
void ssl_proxy_free(struct ssl_proxy **proxy);

/* Return number of active SSL proxies */
unsigned int ssl_proxy_get_count(void) ATTR_PURE;

void ssl_proxy_init(void);
void ssl_proxy_deinit(void);

#endif
