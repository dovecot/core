#ifndef IMAP_PROXY_H
#define IMAP_PROXY_H

#include "login-proxy.h"

int imap_proxy_new(struct imap_client *client, const char *hosts,
		   unsigned int port, const char *user, const char *master_user,
		   const char *password);

#endif
