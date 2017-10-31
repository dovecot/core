#ifndef LMTP_PROXY_H
#define LMTP_PROXY_H

#include "net.h"
#include "smtp-address.h"
#include "smtp-params.h"
#include "smtp-client.h"

#define LMTP_PROXY_DEFAULT_TTL 5

struct smtp_address;
struct lmtp_proxy;
struct client;

typedef void lmtp_proxy_finish_callback_t(void *context);

void lmtp_proxy_deinit(struct lmtp_proxy **proxy);

unsigned int lmtp_proxy_rcpt_count(struct client *client);

int lmtp_proxy_rcpt(struct client *client,
		    struct smtp_address *address,
		    const char *username, const char *detail, char delim,
		    struct smtp_params_rcpt *params);

/* Start proxying */
void lmtp_proxy_start(struct lmtp_proxy *proxy, struct istream *data_input,
		      lmtp_proxy_finish_callback_t *callback, void *context)
	ATTR_NULL(3);


#endif
