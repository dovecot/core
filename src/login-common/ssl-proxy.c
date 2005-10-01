/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ssl-proxy.h"

int ssl_initialized = FALSE;

#ifndef HAVE_SSL

/* no SSL support */

int ssl_proxy_new(int fd __attr_unused__, struct ip_addr *ip __attr_unused__,
		  struct ssl_proxy **proxy_r __attr_unused__)
{
	i_error("Dovecot wasn't built with SSL support");
	return -1;
}

int ssl_proxy_has_valid_client_cert(struct ssl_proxy *proxy __attr_unused__)
{
	return FALSE;
}

const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy __attr_unused__)
{
	return NULL;
}

void ssl_proxy_free(struct ssl_proxy *proxy __attr_unused__) {}

void ssl_proxy_init(void) {}
void ssl_proxy_deinit(void) {}

#endif
