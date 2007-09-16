#ifndef LOGIN_PROXY_H
#define LOGIN_PROXY_H

struct login_proxy;

/* Called when new input comes from proxy. */
typedef void proxy_callback_t(struct istream *input, struct ostream *output,
			      void *context);

/* Create a proxy to given host. Returns NULL if failed. Given callback is
   called when new input is available from proxy. */
struct login_proxy *
login_proxy_new(struct client *client, const char *host, unsigned int port,
		proxy_callback_t *callback, void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define login_proxy_new(client, host, port, callback, context) \
	({(void)(1 ? 0 : callback((struct istream *)NULL, \
				  (struct ostream *)NULL, context)); \
	  login_proxy_new(client, host, port, \
		(proxy_callback_t *)callback, context); })
#else
#  define login_proxy_new(client, host, port, callback, context) \
	  login_proxy_new(client, host, port, \
		(proxy_callback_t *)callback, context)
#endif
/* Free the proxy. This should be called if authentication fails. */
void login_proxy_free(struct login_proxy *proxy);

/* Detach proxy from client. This is done after the authentication is
   successful and all that is left is the dummy proxying. */
void login_proxy_detach(struct login_proxy *proxy, struct istream *client_input,
			struct ostream *client_output);

const char *login_proxy_get_host(struct login_proxy *proxy);
unsigned int login_proxy_get_port(struct login_proxy *proxy);

/* Return number of active detached login proxies */
unsigned int login_proxy_get_count(void);

void login_proxy_deinit(void);

#endif
