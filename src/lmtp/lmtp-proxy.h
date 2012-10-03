#ifndef LMTP_PROXY_H
#define LMTP_PROXY_H

#include "net.h"
#include "lmtp-client.h"

#define LMTP_PROXY_DEFAULT_TTL 5

struct lmtp_proxy_settings {
	const char *my_hostname;
	const char *dns_client_socket_path;
	const char *session_id;

	/* the original client's IP/port that connected to the proxy */
	struct ip_addr source_ip;
	unsigned int source_port;
	unsigned int proxy_ttl;
};

struct lmtp_proxy_rcpt_settings {
	const char *host;
	unsigned int port;
	unsigned int timeout_msecs;
	enum lmtp_client_protocol protocol;
};

typedef void lmtp_proxy_finish_callback_t(void *context);

struct lmtp_proxy *
lmtp_proxy_init(const struct lmtp_proxy_settings *set,
		struct ostream *client_output);
void lmtp_proxy_deinit(struct lmtp_proxy **proxy);

/* Set the "MAIL FROM:" line, including <> and options */
void lmtp_proxy_mail_from(struct lmtp_proxy *proxy, const char *value);
/* Add a new recipient. Returns -1 if we already know that the destination
   host can't be reached. */
int lmtp_proxy_add_rcpt(struct lmtp_proxy *proxy, const char *address,
			const struct lmtp_proxy_rcpt_settings *set);
/* Start proxying */
void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      const char *header,
		      lmtp_proxy_finish_callback_t *callback, void *context)
	ATTR_NULL(3);

#endif
