/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ssl-proxy.h"

bool ssl_initialized = FALSE;

#ifndef HAVE_SSL

/* no SSL support */

int ssl_proxy_new(int fd ATTR_UNUSED, struct ip_addr *ip ATTR_UNUSED,
		  struct ssl_proxy **proxy_r ATTR_UNUSED)
{
	i_error("Dovecot wasn't built with SSL support");
	return -1;
}

bool ssl_proxy_has_valid_client_cert(struct ssl_proxy *proxy ATTR_UNUSED)
{
	return FALSE;
}

const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy ATTR_UNUSED)
{
	return NULL;
}

bool ssl_proxy_is_handshaked(struct ssl_proxy *proxy ATTR_UNUSED)
{
	return FALSE;
}

const char *ssl_proxy_get_last_error(struct ssl_proxy *proxy ATTR_UNUSED)
{
	return NULL;
}

void ssl_proxy_free(struct ssl_proxy *proxy ATTR_UNUSED) {}

unsigned int ssl_proxy_get_count(void)
{
	return 0;
}

void ssl_proxy_init(void) {}
void ssl_proxy_deinit(void) {}

#endif
