#ifndef LMTP_PROXY_H
#define LMTP_PROXY_H

#include "net.h"
#include "smtp-address.h"
#include "smtp-params.h"
#include "smtp-client.h"

#define LMTP_PROXY_DEFAULT_TTL 5

struct smtp_address;
struct client;

struct lmtp_proxy_settings {
	const char *my_hostname;
	const char *session_id;

	/* the original client's IP/port that connected to the proxy */
	struct ip_addr source_ip;
	in_port_t source_port;
	unsigned int proxy_ttl;
};

struct lmtp_proxy_rcpt_settings {
	enum smtp_protocol protocol;
	const char *host;
	struct ip_addr hostip;
	in_port_t port;
	unsigned int timeout_msecs;
	struct smtp_params_rcpt params;
};

typedef void lmtp_proxy_finish_callback_t(void *context);

struct lmtp_proxy *
lmtp_proxy_init(const struct lmtp_proxy_settings *set,
		struct ostream *client_output);
void lmtp_proxy_deinit(struct lmtp_proxy **proxy);

/* Set the "MAIL FROM:" parameters */
void lmtp_proxy_mail_from(struct lmtp_proxy *proxy,
			  const struct smtp_address *address,
			  const struct smtp_params_mail *params);
/* Add a new recipient. Returns -1 if we already know that the destination
   host can't be reached. */
int lmtp_proxy_add_rcpt(struct lmtp_proxy *proxy,
			const struct smtp_address *address,
			const struct lmtp_proxy_rcpt_settings *set);

bool lmtp_proxy_rcpt(struct client *client,
		     struct smtp_address *address,
		     const char *username, const char *detail, char delim,
		     struct smtp_params_rcpt *params);

/* Start proxying */
void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      lmtp_proxy_finish_callback_t *callback, void *context)
	ATTR_NULL(3);


#endif
