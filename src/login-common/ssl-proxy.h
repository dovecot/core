#ifndef SSL_PROXY_H
#define SSL_PROXY_H

struct ip_addr;
struct ssl_proxy;

extern bool ssl_initialized;

/* establish SSL connection with the given fd, returns a new fd which you
   must use from now on, or -1 if error occurred. Unless -1 is returned,
   the given fd must be simply forgotten. */
int ssl_proxy_new(int fd, struct ip_addr *ip, struct ssl_proxy **proxy_r);
bool ssl_proxy_has_valid_client_cert(const struct ssl_proxy *proxy) ATTR_PURE;
const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy);
bool ssl_proxy_is_handshaked(const struct ssl_proxy *proxy) ATTR_PURE;
const char *ssl_proxy_get_last_error(const struct ssl_proxy *proxy) ATTR_PURE;
const char *ssl_proxy_get_security_string(struct ssl_proxy *proxy);
void ssl_proxy_free(struct ssl_proxy *proxy);

/* Return number of active SSL proxies */
unsigned int ssl_proxy_get_count(void) ATTR_PURE;

void ssl_proxy_init(void);
void ssl_proxy_deinit(void);

#endif
