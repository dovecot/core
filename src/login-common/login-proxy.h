#ifndef __LOGIN_PROXY_H
#define __LOGIN_PROXY_H

struct login_proxy;

/* Called when new input comes from proxy. */
typedef void proxy_callback_t(struct istream *input, struct ostream *output,
			      void *context);

/* Create a proxy to given host. Returns NULL if failed. Given callback is
   called when new input is available from proxy. */
struct login_proxy *
login_proxy_new(struct client *client, const char *host, unsigned int port,
		proxy_callback_t *callback, void *context);
/* Free the proxy. This should be called if authentication fails. */
void login_proxy_free(struct login_proxy *proxy);

/* Detach proxy from client. This is done after the authentication is
   successful and all that is left is the dummy proxying. */
void login_proxy_detach(struct login_proxy *proxy, struct istream *client_input,
			struct ostream *client_output);

void login_proxy_deinit(void);

#endif
