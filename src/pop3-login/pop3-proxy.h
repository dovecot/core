#ifndef POP3_PROXY_H
#define POP3_PROXY_H

#include "login-proxy.h"

int pop3_proxy_new(struct pop3_client *client, const char *host,
		   unsigned int port, const char *user, const char *password);

#endif
