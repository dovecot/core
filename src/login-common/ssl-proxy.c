/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ssl-proxy.h"

int ssl_initialized = FALSE;

#ifndef HAVE_SSL

/* no SSL support */

int ssl_proxy_new(int fd __attr_unused__, struct ip_addr *ip __attr_unused__,
		  struct ssl_proxy **proxy_r __attr_unused__)
{
	return -1;
}

int ssl_proxy_has_valid_client_cert(struct ssl_proxy *proxy __attr_unused__)
{
	return FALSE;
}

void ssl_proxy_init(void) {}
void ssl_proxy_deinit(void) {}

#endif
