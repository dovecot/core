/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"

int ssl_initialized = FALSE;

#ifndef HAVE_SSL

/* no SSL support */

int ssl_proxy_new(int fd __attr_unused__) { return -1; }
void ssl_proxy_init(void) {}
void ssl_proxy_deinit(void) {}

#endif
